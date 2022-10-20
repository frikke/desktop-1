/*
 * Copyright (C) by Oleksandr Zolotov <alex@nextcloud.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 */

#include "shellextensionsserver.h"
#include "account.h"
#include "accountstate.h"
#include "common/shellextensionutils.h"
#include <libsync/vfs/cfapi/shellext/configvfscfapishellext.h>
#include "folder.h"
#include "folderman.h"
#include "ocssharejob.h"
#include <QDir>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLocalSocket>

namespace {
constexpr auto isSharedInvalidationInterval = 2 * 60 * 1000; // 2 minutes, so we don't make fetch sharees requests too often
constexpr auto folderAliasPropertyKey = "folderAlias";
}

namespace OCC {

Q_LOGGING_CATEGORY(lcShellExtServer, "nextcloud.gui.shellextensions.server", QtInfoMsg)

ShellExtensionsServer::ShellExtensionsServer(QObject *parent)
    : QObject(parent)
{
    _isSharedInvalidationInterval = isSharedInvalidationInterval;
    _localServer.listen(VfsShellExtensions::serverNameForApplicationNameDefault());
    connect(&_localServer, &QLocalServer::newConnection, this, &ShellExtensionsServer::slotNewConnection);
}

ShellExtensionsServer::~ShellExtensionsServer()
{
    for (const auto &connection : _customStateSocketConnections) {
        if (connection) {
            QObject::disconnect(connection);
        }
    }
    _customStateSocketConnections.clear();

    if (!_localServer.isListening()) {
        return;
    }
    _localServer.close();
}

QString ShellExtensionsServer::getFetchThumbnailPath()
{
    return QStringLiteral("/index.php/core/preview");
}

void ShellExtensionsServer::setIsSharedInvalidationInterval(qint64 interval)
{
    _isSharedInvalidationInterval = interval;
}

void ShellExtensionsServer::sendJsonMessageWithVersion(QLocalSocket *socket, const QVariantMap &message)
{
    socket->write(VfsShellExtensions::Protocol::createJsonMessage(message));
    socket->waitForBytesWritten();
}

void ShellExtensionsServer::sendEmptyDataAndCloseSession(QLocalSocket *socket)
{
    sendJsonMessageWithVersion(socket, QVariantMap{});
    closeSession(socket);
}

void ShellExtensionsServer::closeSession(QLocalSocket *socket)
{
    connect(socket, &QLocalSocket::disconnected, this, [socket] {
        socket->close();
        socket->deleteLater();
    });
    socket->disconnectFromServer();
}

void ShellExtensionsServer::processCustomStateRequest(QLocalSocket *socket, const CustomStateRequestInfo &customStateRequestInfo)
{
    if (!customStateRequestInfo.isValid()) {
        sendEmptyDataAndCloseSession(socket);
        return;
    }

    const auto folder = FolderMan::instance()->folder(customStateRequestInfo.folderAlias);

    if (!folder) {
        sendEmptyDataAndCloseSession(socket);
        return;
    }
    const auto filePathRelative = QString(customStateRequestInfo.path).remove(folder->path());

    SyncJournalFileRecord record;
    if (!folder->journalDb()->getFileRecord(filePathRelative, &record) || !record.isValid() || record.path().isEmpty()) {
        qCWarning(lcShellExtServer) << "Record not found in SyncJournal for: " << filePathRelative;
        sendEmptyDataAndCloseSession(socket);
        return;
    }

    const auto composeMessageReplyFromRecord = [](const SyncJournalFileRecord &record) {
        QVariantList states;
        if (record._lockstate._locked) {
            states.push_back(QString(CUSTOM_STATE_ICON_LOCKED_INDEX).toInt() - QString(CUSTOM_STATE_ICON_INDEX_OFFSET).toInt());
        }
        if (record._isShared) {
            states.push_back(QString(CUSTOM_STATE_ICON_SHARED_INDEX).toInt() - QString(CUSTOM_STATE_ICON_INDEX_OFFSET).toInt());
        }
        return QVariantMap{{VfsShellExtensions::Protocol::CustomStateDataKey,
            QVariantMap{{VfsShellExtensions::Protocol::CustomStateStatesKey, states}}}};
    };

    if (QDateTime::currentMSecsSinceEpoch() - record._lastShareStateFetchedTimestmap < _isSharedInvalidationInterval) {
        qCInfo(lcShellExtServer) << record.path() << " record._lastShareStateFetchedTimestmap has less than " << _isSharedInvalidationInterval << " ms difference with QDateTime::currentMSecsSinceEpoch(). Returning data from SyncJournal.";
        sendJsonMessageWithVersion(socket, composeMessageReplyFromRecord(record));
        closeSession(socket);
        return;
    }

    {
        _customStateSocketConnections.insert(socket->socketDescriptor(), QObject::connect(this, &ShellExtensionsServer::fetchPermissionsJobFinished, [this, socket, filePathRelative, composeMessageReplyFromRecord](const QString &folderAlias) {
            {
                const auto connection = _customStateSocketConnections[socket->socketDescriptor()];
                if (connection) {
                    QObject::disconnect(connection);
                }
                _customStateSocketConnections.remove(socket->socketDescriptor());
            }
            
            const auto folder = FolderMan::instance()->folder(folderAlias);
            SyncJournalFileRecord record;
            if (!folder || !folder->journalDb()->getFileRecord(filePathRelative, &record) || !record.isValid()) {
                qCWarning(lcShellExtServer) << "Record not found in SyncJournal for: " << filePathRelative;
                sendEmptyDataAndCloseSession(socket);
                return;
            }
            
            qCInfo(lcShellExtServer) << "Sending reply from OcsShareJob for socket: " << socket->socketDescriptor() << " and record: " << record.path();
            sendJsonMessageWithVersion(socket, composeMessageReplyFromRecord(record));
            closeSession(socket);
        }));
    }

    const auto sharesPath = [&record, folder, &filePathRelative]() {
        const auto filePathRelativeRemote = QDir(folder->remotePath()).filePath(filePathRelative);
        // either get parent's path, or, return '/' if we are in the root folder
        auto recordPathSplit = filePathRelativeRemote.split(QLatin1Char('/'), Qt::SkipEmptyParts);
        if (recordPathSplit.size() > 1) {
            recordPathSplit.removeLast();
            return recordPathSplit.join(QLatin1Char('/'));
        }
        return QStringLiteral("/");
    }();

    auto *lsColJob = new LsColJob(folder->accountState()->account(), QDir::cleanPath(folder->remotePath() + filePathRelative), this);

    QList<QByteArray> props;
    props << "resourcetype"
          << "http://owncloud.org/ns:share-types"
          << "http://owncloud.org/ns:permissions";

    lsColJob->setProperties(props);

    lsColJob->setProperties(props);

    QObject::connect(lsColJob, &LsColJob::directoryListingIterated, this, [this](const QString &name, const QMap<QString, QString> &properties) {
        auto a = name;
        int b = 5;
        b = 6;
    });

    QObject::connect(lsColJob, &LsColJob::finishedWithError, this, [this](QNetworkReply *reply) {
        int a = 5;
        a = 6;
    });
    QObject::connect(lsColJob, &LsColJob::finishedWithoutError, this, [this]() {
        int a = 5;
        a = 6;
    });
    lsColJob->start();

    const auto propfindJob = new PropfindJob(folder->accountState()->account(), QDir::cleanPath(folder->remotePath() + filePathRelative));
    propfindJob->setProperties({"http://owncloud.org/ns:permissions", "http://owncloud.org/ns:share-types"});
    propfindJob->setProperty(folderAliasPropertyKey, customStateRequestInfo.folderAlias);
    connect(propfindJob, &PropfindJob::result, this, &ShellExtensionsServer::slotPermissionsFetched);
    connect(propfindJob, &PropfindJob::finishedWithError, this, &ShellExtensionsServer::slotPermissionsFetchError);

    if (!_runningFetchShareJobsForPaths.contains(filePathRelative)) {
        _runningFetchShareJobsForPaths.push_back(filePathRelative);
        qCInfo(lcShellExtServer) << "Started PropfindJob for item: " << filePathRelative;
        propfindJob->start();
    } else {
        qCInfo(lcShellExtServer) << "PropfindJob is already running for path: " << filePathRelative;
    }
}

void ShellExtensionsServer::processThumbnailRequest(QLocalSocket *socket, const ThumbnailRequestInfo &thumbnailRequestInfo)
{
    if (!thumbnailRequestInfo.isValid()) {
        sendEmptyDataAndCloseSession(socket);
        return;
    }

    const auto folder = FolderMan::instance()->folder(thumbnailRequestInfo.folderAlias);

    if (!folder) {
        sendEmptyDataAndCloseSession(socket);
        return;
    }

    const auto fileInfo = QFileInfo(thumbnailRequestInfo.path);
    const auto filePathRelative = QFileInfo(thumbnailRequestInfo.path).canonicalFilePath().remove(folder->path());

    SyncJournalFileRecord record;
    if (!folder->journalDb()->getFileRecord(filePathRelative, &record) || !record.isValid()) {
        sendEmptyDataAndCloseSession(socket);
        return;
    }

    QUrlQuery queryItems;
    queryItems.addQueryItem(QStringLiteral("fileId"), record._fileId);
    queryItems.addQueryItem(QStringLiteral("x"), QString::number(thumbnailRequestInfo.size.width()));
    queryItems.addQueryItem(QStringLiteral("y"), QString::number(thumbnailRequestInfo.size.height()));
    const QUrl jobUrl = Utility::concatUrlPath(folder->accountState()->account()->url(), getFetchThumbnailPath(), queryItems);
    const auto job = new SimpleNetworkJob(folder->accountState()->account());
    job->startRequest(QByteArrayLiteral("GET"), jobUrl);
    connect(job, &SimpleNetworkJob::finishedSignal, this, [socket, this](QNetworkReply *reply) {
        const auto contentType = reply->header(QNetworkRequest::ContentTypeHeader).toByteArray();
        if (!contentType.startsWith(QByteArrayLiteral("image/"))) {
            sendEmptyDataAndCloseSession(socket);
            return;
        }
        
        auto messageReplyWithThumbnail = QVariantMap {
            {VfsShellExtensions::Protocol::ThumnailProviderDataKey, reply->readAll().toBase64()}
        };
        sendJsonMessageWithVersion(socket, messageReplyWithThumbnail);
        closeSession(socket);
    });
}

void ShellExtensionsServer::slotNewConnection()
{
    const auto socket = _localServer.nextPendingConnection();

    if (!socket) {
        return;
    }

    socket->waitForReadyRead();
    const auto message = QJsonDocument::fromJson(socket->readAll()).toVariant().toMap();

    if (!VfsShellExtensions::Protocol::validateProtocolVersion(message)) {
        sendEmptyDataAndCloseSession(socket);
        return;
    }

    if (message.contains(VfsShellExtensions::Protocol::ThumbnailProviderRequestKey)) {
        parseThumbnailRequest(socket, message);
        return;
    } else if (message.contains(VfsShellExtensions::Protocol::CustomStateProviderRequestKey)) {
        parseCustomStateRequest(socket, message);
        return;
    }
    qCWarning(lcShellExtServer) << "Invalid message received from shell extension: " << message;
    sendEmptyDataAndCloseSession(socket);
    return;
}

void ShellExtensionsServer::slotPermissionsFetched(const QVariantMap &values)
{
    const auto job = qobject_cast<PropfindJob *>(sender());

    Q_ASSERT(job);
    if (!job) {
        qCWarning(lcShellExtServer) << "ShellExtensionsServer::slotPermissionsFetched is not called by PropfindJob's signal!";
        return;
    }

    const auto filePath = job->path();

    const auto filePathAdjusted = filePath.startsWith(QLatin1Char('/')) ? QString(filePath).remove(0, 1) : filePath;

    _runningFetchShareJobsForPaths.removeAll(filePathAdjusted);

    const auto folderAlias = job->property(folderAliasPropertyKey).toString();

    Q_ASSERT(!folderAlias.isEmpty());
    if (folderAlias.isEmpty()) {
        qCWarning(lcShellExtServer) << "No 'folderAlias' set for OcsShareJob's instance!";
        return;
    }

    const auto folder = FolderMan::instance()->folder(folderAlias);

    Q_ASSERT(folder);
    if (!folder) {
        qCWarning(lcShellExtServer) << "folder not found for folderAlias: " << folderAlias;
        emit fetchPermissionsJobFinished(folderAlias);
        return;
    }

    SyncJournalFileRecord record;
    if (!folder || !folder->journalDb()->getFileRecord(filePathAdjusted, &record) || !record.isValid()) {
        emit fetchPermissionsJobFinished(folderAlias);
        return;
    }
    record._isShared = values.contains(QStringLiteral("permissions"))
        && RemotePermissions::fromServerString(values[QStringLiteral("permissions")].toString()).hasPermission(OCC::RemotePermissions::IsShared);

    record._lastShareStateFetchedTimestmap = QDateTime::currentMSecsSinceEpoch();

    if (!folder->journalDb()->setFileRecord(record)) {
        qCWarning(lcShellExtServer) << "Could not set file record for path: " << record._path;
        emit fetchPermissionsJobFinished(folderAlias);
        return;
    }

    qCInfo(lcShellExtServer) << "Succeeded PropfindJob for path: " << filePathAdjusted;
    emit fetchPermissionsJobFinished(folderAlias);
}

void ShellExtensionsServer::slotPermissionsFetchError(QNetworkReply *reply)
{
    const auto job = qobject_cast<PropfindJob *>(sender());

    Q_ASSERT(job);
    if (!job) {
        qCWarning(lcShellExtServer) << "ShellExtensionsServer::slotSharesFetched is not called by PropfindJob's signal!";
        return;
    }

    const auto filePath = job->path();

    _runningFetchShareJobsForPaths.removeAll(filePath);

    emit fetchPermissionsJobFinished(filePath);
    qCWarning(lcShellExtServer) << "Failed PropfindJob for filePath: " << filePath;
}

void ShellExtensionsServer::parseCustomStateRequest(QLocalSocket *socket, const QVariantMap &message)
{
    const auto customStateRequestMessage = message.value(VfsShellExtensions::Protocol::CustomStateProviderRequestKey).toMap();
    const auto itemFilePath = QDir::fromNativeSeparators(customStateRequestMessage.value(VfsShellExtensions::Protocol::FilePathKey).toString());

    if (itemFilePath.isEmpty()) {
        sendEmptyDataAndCloseSession(socket);
        return;
    }

    QString foundFolderAlias;
    for (const auto folder : FolderMan::instance()->map()) {
        if (itemFilePath.startsWith(folder->path())) {
            foundFolderAlias = folder->alias();
            break;
        }
    }

    if (foundFolderAlias.isEmpty()) {
        sendEmptyDataAndCloseSession(socket);
        return;
    }
    
    const auto customStateRequestInfo = CustomStateRequestInfo {
        itemFilePath,
        foundFolderAlias
    };

    processCustomStateRequest(socket, customStateRequestInfo);
}

void ShellExtensionsServer::parseThumbnailRequest(QLocalSocket *socket, const QVariantMap &message)
{
    const auto thumbnailRequestMessage = message.value(VfsShellExtensions::Protocol::ThumbnailProviderRequestKey).toMap();
    const auto thumbnailFilePath = QDir::fromNativeSeparators(thumbnailRequestMessage.value(VfsShellExtensions::Protocol::FilePathKey).toString());
    const auto thumbnailFileSize = thumbnailRequestMessage.value(VfsShellExtensions::Protocol::ThumbnailProviderRequestFileSizeKey).toMap();

    if (thumbnailFilePath.isEmpty() || thumbnailFileSize.isEmpty()) {
        sendEmptyDataAndCloseSession(socket);
        return;
    }

    QString foundFolderAlias;
    for (const auto folder : FolderMan::instance()->map()) {
        if (thumbnailFilePath.startsWith(folder->path())) {
            foundFolderAlias = folder->alias();
            break;
        }
    }

    if (foundFolderAlias.isEmpty()) {
        sendEmptyDataAndCloseSession(socket);
        return;
    }

    const auto thumbnailRequestInfo = ThumbnailRequestInfo {
        thumbnailFilePath,
        QSize(thumbnailFileSize.value("width").toInt(), thumbnailFileSize.value("height").toInt()),
        foundFolderAlias
    };

    processThumbnailRequest(socket, thumbnailRequestInfo);
}

} // namespace OCC
