/*
 * Copyright (C) 2023 by Oleksandr Zolotov <alex@nextcloud.com>
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

#include "updatee2eefolderusersmetadatajob.h"
#include "clientsideencryption.h"
#include "clientsideencryptionjobs.h"
#include "foldermetadata.h"
#include "common/syncjournalfilerecord.h"
#include "common/syncjournaldb.h"

namespace OCC
{
Q_LOGGING_CATEGORY(lcUpdateE2eeFolderUsersMetadataJob, "nextcloud.gui.updatee2eefolderusersmetadatajob", QtInfoMsg)

UpdateE2eeFolderUsersMetadataJob::UpdateE2eeFolderUsersMetadataJob(const AccountPtr &account,
                                                       SyncJournalDb *journalDb,
                                                       const QString &syncFolderRemotePath,
                                                       const Operation operation,
                                                       const QString &path,
                                                       const QString &folderUserId,
                                                       QSslCertificate certificate,
                                                       QObject *parent)
    : QObject{parent}
    , _account(account)
    , _journalDb(journalDb)
    , _syncFolderRemotePath(syncFolderRemotePath)
    , _operation(operation)
    , _path(path)
    , _folderUserId(folderUserId)
    , _folderUserCertificate(certificate)
{
    if (_operation == Operation::Add) {
        connect(this, &UpdateE2eeFolderUsersMetadataJob::certificateReady, this, &UpdateE2eeFolderUsersMetadataJob::slotCertificateReady);
    }
    connect(this, &UpdateE2eeFolderUsersMetadataJob::finished, this, &UpdateE2eeFolderUsersMetadataJob::deleteLater);
}

QString UpdateE2eeFolderUsersMetadataJob::path() const
{
    return _path;
}

QVariant UpdateE2eeFolderUsersMetadataJob::userData() const
{
    return _userData;
}

SyncFileItem::EncryptionStatus UpdateE2eeFolderUsersMetadataJob::encryptionStatus() const
{
    return FolderMetadata::fromMedataVersionToItemEncryptionStatus(_folderMetadata->encryptedMetadataVersion());
}

void UpdateE2eeFolderUsersMetadataJob::start()
{
    if (!_journalDb) {
        emit finished(404, tr("Could not find local folder for %1").arg(QString::fromUtf8(_folderId)));
        return;
    }

    qDebug() << "Folder is encrypted, let's get the Id from it.";
    const auto pathSanitized = _path.startsWith(QLatin1Char('/')) ? _path.mid(1) : _path;
    const auto fetchFolderEncryptedIdJob = new LsColJob(_account, _syncFolderRemotePath + pathSanitized, this);
    fetchFolderEncryptedIdJob->setProperties({"resourcetype", "http://owncloud.org/ns:fileid"});
    connect(fetchFolderEncryptedIdJob, &LsColJob::directoryListingSubfolders, this, &UpdateE2eeFolderUsersMetadataJob::slotFolderEncryptedIdReceived);
    connect(fetchFolderEncryptedIdJob, &LsColJob::finishedWithError, this, &UpdateE2eeFolderUsersMetadataJob::slotFolderEncryptedIdError);
    fetchFolderEncryptedIdJob->start();
}

void UpdateE2eeFolderUsersMetadataJob::startUpdate()
{
    if (!_journalDb) {
        emit finished(404, tr("Could not find local folder for %1").arg(QString::fromUtf8(_folderId)));
        return;
    }

    switch (_operation) {
    case Operation::Add:
        if (!_folderUserCertificate.isNull()) {
            emit certificateReady();
            return;
        }
        connect(_account->e2e(),
                &ClientSideEncryption::certificateFetchedFromKeychain,
                this,
                &UpdateE2eeFolderUsersMetadataJob::slotCertificateFetchedFromKeychain);
        _account->e2e()->fetchFromKeyChain(_account, _folderUserId);
        return;
    case Operation::Remove:
        slotLockFolder();
        return;
    case Operation::ReEncrypt:
        slotFetchFolderMetadata();
        return;
    }

    emit finished(404,
                  tr("Invalid folder user update metadata operation for a folder user %1, for folder %2").arg(_folderUserId).arg(QString::fromUtf8(_folderId)));
}

void UpdateE2eeFolderUsersMetadataJob::setUserData(const QVariant &userData)
{
    _userData = userData;
}

void UpdateE2eeFolderUsersMetadataJob::setFolderToken(const QByteArray &folderToken)
{
    _folderToken = folderToken;
}

void UpdateE2eeFolderUsersMetadataJob::setMetadataKeyForEncryption(const QByteArray &metadataKey)
{
    _metadataKeyForEncryption = metadataKey;
}

void UpdateE2eeFolderUsersMetadataJob::setMetadataKeyForDecryption(const QByteArray &metadataKey)
{
    _metadataKeyForDecryption = metadataKey;
}

void UpdateE2eeFolderUsersMetadataJob::setKeyChecksums(const QSet<QByteArray> &keyChecksums)
{
    _keyChecksums = keyChecksums;
}

void UpdateE2eeFolderUsersMetadataJob::slotCertificateFetchedFromKeychain(const QSslCertificate certificate)
{
    disconnect(_account->e2e(), &ClientSideEncryption::certificateFetchedFromKeychain, this, &UpdateE2eeFolderUsersMetadataJob::slotCertificateFetchedFromKeychain);
    if (certificate.isNull()) {
        // get folder user's public key
        _account->e2e()->getUsersPublicKeyFromServer(_account, {_folderUserId});
        connect(_account->e2e(), &ClientSideEncryption::certificatesFetchedFromServer, this, &UpdateE2eeFolderUsersMetadataJob::slotCertificatesFetchedFromServer);
        return;
    }
    _folderUserCertificate = certificate;
    emit certificateReady();
}

void UpdateE2eeFolderUsersMetadataJob::slotCertificatesFetchedFromServer(const QHash<QString, QSslCertificate> &results)
{
    const auto certificate = results.isEmpty() ? QSslCertificate{} : results.value(_folderUserId);
    if (certificate.isNull()) {
        emit certificateReady();
        return;
    }
    _account->e2e()->writeCertificate(_account, _folderUserId, certificate);
    connect(_account->e2e(), &ClientSideEncryption::certificateWriteComplete, this, &UpdateE2eeFolderUsersMetadataJob::certificateReady);
}

void UpdateE2eeFolderUsersMetadataJob::slotCertificateReady()
{
    if (_folderUserCertificate.isNull()) {
        emit finished(404, tr("Could not fetch publicKey for user %1").arg(_folderUserId));
    } else {
        slotLockFolder();
    }
}

void UpdateE2eeFolderUsersMetadataJob::slotFetchFolderMetadata()
{
    const auto job = new GetMetadataApiJob(_account, _folderId);
    connect(job, &GetMetadataApiJob::jsonReceived, this, &UpdateE2eeFolderUsersMetadataJob::slotMetadataReceived);
    connect(job, &GetMetadataApiJob::error, this, &UpdateE2eeFolderUsersMetadataJob::slotMetadataError);
    job->start();
}

void UpdateE2eeFolderUsersMetadataJob::slotFolderEncryptedIdReceived(const QStringList &list)
{
    qDebug() << "Received id of folder, trying to lock it so we can prepare the metadata";
    const auto fetchFolderEncryptedIdJob = qobject_cast<LsColJob *>(sender());
    Q_ASSERT(fetchFolderEncryptedIdJob);
    if (!fetchFolderEncryptedIdJob) {
        qCritical() << "slotFolderEncryptedIdReceived must be called by a signal";
        emit finished(SyncFileItem::Status::FatalError);
        return;
    }
    Q_ASSERT(!list.isEmpty());
    if (list.isEmpty()) {
        qCritical() << "slotFolderEncryptedIdReceived list.isEmpty()";
        emit finished(SyncFileItem::Status::FatalError);
        return;
    }
    const auto &folderInfo = fetchFolderEncryptedIdJob->_folderInfos.value(list.first());
    _folderId = folderInfo.fileId;
    startUpdate();
}

void UpdateE2eeFolderUsersMetadataJob::slotFolderEncryptedIdError(QNetworkReply *r)
{
    Q_UNUSED(r);
    qCritical() << "Error retrieving the Id of the encrypted folder.";
    emit finished(SyncFileItem::Status::FatalError);
}

void UpdateE2eeFolderUsersMetadataJob::slotMetadataReceived(const QJsonDocument &json, int statusCode)
{
    qCDebug(lcUpdateE2eeFolderUsersMetadataJob) << "Metadata received, applying it to the result list";
    if (!_journalDb) {
        emit finished(404, tr("Could not find local folder for %1").arg(QString::fromUtf8(_folderId)));
        return;
    }
    SyncJournalFileRecord rec;
    if (!_journalDb->getTopLevelE2eFolderRecord(_path, &rec) || !rec.isValid()) {
        emit finished(-1, tr("Could not find top level E2EE folder for %1").arg(QString::fromUtf8(_folderId)));
        return;
    }
    const auto pathSanitized = _path.startsWith(QLatin1Char('/')) ? _path.mid(1) : _path;
    const auto rootE2eeFolderPath = rec.path() == pathSanitized ? QStringLiteral("/") : rec.path();
    const FolderMetadata::RootEncryptedFolderInfo topLevelInitData(
        rootE2eeFolderPath,
        _metadataKeyForEncryption,
        _metadataKeyForDecryption,
        _keyChecksums
    );
    _folderMetadata.reset(new FolderMetadata(_account, statusCode == 404 ? QByteArray{} : json.toJson(QJsonDocument::Compact), topLevelInitData));
    _folderMetadata->setKeyChecksums(_keyChecksums);
    connect(_folderMetadata.data(), &FolderMetadata::setupComplete, this, [this] {
        if (!_folderMetadata->isValid()) {
            slotUnlockFolder();
            return;
        }
        if (_operation == Operation::ReEncrypt) {
            slotUpdateFolderMetadata();
            return;
        }
        if (_operation == Operation::Add || _operation == Operation::Remove) {
            bool result = false;
            if (_operation == Operation::Add) {
                result = _folderMetadata->addUser(_folderUserId, _folderUserCertificate);
            } else if (_operation == Operation::Remove) {
                result = _folderMetadata->removeUser(_folderUserId);
            }

            if (!result) {
                emit finished(403, tr("Could not add or remove a folder user %1, for folder %2").arg(_folderUserId).arg(_path));
                return;
            }

            slotUpdateFolderMetadata();
            return;
        }
        emit finished(-1, tr("Wrong operation for folder %1").arg(QString::fromUtf8(_folderId)));
    });
}

void UpdateE2eeFolderUsersMetadataJob::slotMetadataError(const QByteArray &folderId, int httpReturnCode)
{
    qCWarning(lcUpdateE2eeFolderUsersMetadataJob) << "E2EE Metadata job error. Trying to proceed without it." << folderId << httpReturnCode;
    emit finished(404, tr("Could not fetch metadata for folder %1").arg(QString::fromUtf8(_folderId)));
}

void UpdateE2eeFolderUsersMetadataJob::slotScheduleSubJobs()
{
    const auto pathInDb = _path.mid(_syncFolderRemotePath.size());

    [[maybe_unused]] const auto result = _journalDb->getFilesBelowPath(pathInDb.toUtf8(), [this](const SyncJournalFileRecord &record) {
        if (record.isDirectory()) {
            const auto subJob = new UpdateE2eeFolderUsersMetadataJob(_account, _journalDb, _syncFolderRemotePath, UpdateE2eeFolderUsersMetadataJob::ReEncrypt, QString::fromUtf8(record._e2eMangledName));
            subJob->setMetadataKeyForEncryption(_folderMetadata->metadataKeyForEncryption());
            subJob->setMetadataKeyForDecryption(_folderMetadata->metadataKeyForDecryption());
            subJob->setKeyChecksums(_folderMetadata->keyChecksums());
            subJob->setParent(this);
            subJob->setFolderToken(_folderToken);
            _subJobs.insert(subJob);
            _pathsForDbRecordsToUpdate.push_back(record._path);
            connect(subJob, &UpdateE2eeFolderUsersMetadataJob::finished, this, &UpdateE2eeFolderUsersMetadataJob::slotSubJobFinished);
        }
    });
}

void UpdateE2eeFolderUsersMetadataJob::slotLockFolder()
{
    Q_ASSERT(_operation == Operation::Add || _operation == Operation::ReEncrypt);
    if (_operation != Operation::Add && _operation != Operation::Remove) {
        emit finished(-1);
        return;
    }
    if (!_journalDb) {
        emit finished(404, tr("Could not find local folder for %1").arg(QString::fromUtf8(_folderId)));
        return;
    }
    const auto lockJob = new LockEncryptFolderApiJob(_account, _folderId, _journalDb, _account->e2e()->_publicKey, this);
    connect(lockJob, &LockEncryptFolderApiJob::success, this, &UpdateE2eeFolderUsersMetadataJob::slotFolderLockedSuccessfully);
    connect(lockJob, &LockEncryptFolderApiJob::error, this, &UpdateE2eeFolderUsersMetadataJob::slotFolderLockedError);
    lockJob->start();
}

void UpdateE2eeFolderUsersMetadataJob::slotUnlockFolder()
{
    if (!_journalDb) {
        emit finished(404, tr("Could not find local folder for %1").arg(QString::fromUtf8(_folderId)));
        return;
    }

    qCDebug(lcUpdateE2eeFolderUsersMetadataJob) << "Calling Unlock";
    const auto unlockJob = new UnlockEncryptFolderApiJob(_account, _folderId, _folderToken, _journalDb, this);
    connect(unlockJob, &UnlockEncryptFolderApiJob::success, [this](const QByteArray &folderId) {
        qCDebug(lcUpdateE2eeFolderUsersMetadataJob) << "Successfully Unlocked";
        _folderToken.clear();
        _folderId.clear();

        for (const auto &recordPath : _pathsForDbRecordsToUpdate) {
            SyncJournalFileRecord rec;
            [[maybe_unused]] const auto resultGet = _journalDb->getFileRecord(recordPath, &rec);
            rec._e2eEncryptionStatus = EncryptionStatusEnums::toDbEncryptionStatus(
                FolderMetadata::fromMedataVersionToItemEncryptionStatus(_folderMetadata->encryptedMetadataVersion()));
            [[maybe_unused]] const auto resultSet = _journalDb->setFileRecord(rec);
        }

        slotFolderUnlocked(folderId, 200);
    });
    connect(unlockJob, &UnlockEncryptFolderApiJob::error, [this](const QByteArray &folderId, int httpStatus) {
        qCDebug(lcUpdateE2eeFolderUsersMetadataJob) << "Unlock Error";
        slotFolderUnlocked(folderId, httpStatus);
    });
    unlockJob->start();
}

void UpdateE2eeFolderUsersMetadataJob::slotFolderLockedSuccessfully(const QByteArray &folderId, const QByteArray &token)
{
    qCDebug(lcUpdateE2eeFolderUsersMetadataJob) << "Folder" << folderId << "Locked Successfully for Upload, Fetching Metadata";
    _folderToken = token;
    Q_ASSERT(_operation == Operation::Add || _operation == Operation::Remove);
    slotFetchFolderMetadata();
}

void UpdateE2eeFolderUsersMetadataJob::slotUpdateMetadataSuccess(const QByteArray &folderId)
{
    Q_UNUSED(folderId);
    qCDebug(lcUpdateE2eeFolderUsersMetadataJob) << "Uploading of the metadata success, Encrypting the file";
    if (_operation == Operation::Add || _operation == Operation::Remove) {
        slotScheduleSubJobs();
        if (_subJobs.isEmpty()) {
            slotUnlockFolder();
        } else {
            _subJobs.values().last()->start();
        }
    } else {
        emit finished(200);
    }
}

void UpdateE2eeFolderUsersMetadataJob::slotUpdateMetadataError(const QByteArray &folderId, int httpErrorResponse)
{
    qCDebug(lcUpdateE2eeFolderUsersMetadataJob) << "Update metadata error for folder" << folderId << "with error" << httpErrorResponse;
    qCDebug(lcUpdateE2eeFolderUsersMetadataJob()) << "Unlocking the folder.";
    if (_operation == Operation::Add || _operation == Operation::Remove) {
        slotUnlockFolder();
    } else {
        emit finished(httpErrorResponse, tr("Failed to update folder metadata."));
    }
}

void UpdateE2eeFolderUsersMetadataJob::slotFolderUnlocked(const QByteArray &folderId, int httpStatus)
{
    const QString message = httpStatus != 200 ? tr("Failed to unlock a folder.") : QString{};
    emit finished(httpStatus, message);
}

void UpdateE2eeFolderUsersMetadataJob::slotUpdateFolderMetadata()
{
    const auto encryptedMetadata = _folderMetadata->encryptedMetadata();
    if (encryptedMetadata.isEmpty()) {
        emit finished(-1, tr("Could not setup metadata for a folder %1").arg(QString::fromUtf8(_folderId)));
        return;
    }
    const auto job = new UpdateMetadataApiJob(_account, _folderId, encryptedMetadata, _folderToken);
    connect(job, &UpdateMetadataApiJob::success, this, &UpdateE2eeFolderUsersMetadataJob::slotUpdateMetadataSuccess);
    connect(job, &UpdateMetadataApiJob::error, this, &UpdateE2eeFolderUsersMetadataJob::slotUpdateMetadataError);
    job->start();
}

void UpdateE2eeFolderUsersMetadataJob::slotSubJobsFinished()
{
    slotUnlockFolder();
}

void UpdateE2eeFolderUsersMetadataJob::slotSubJobFinished(int code, const QString &message)
{
    Q_UNUSED(message);
    if (code != 200) {
        _pathsForDbRecordsToUpdate.clear();
        slotUnlockFolder();
        return;
    }
    const auto job = qobject_cast<UpdateE2eeFolderUsersMetadataJob *>(sender());
    Q_ASSERT(job);
    if (!job) {
        slotUnlockFolder();
        return;
    }
    _subJobs.remove(job);
    job->deleteLater();

    if (_subJobs.isEmpty()) {
        slotSubJobsFinished();
    } else {
        _subJobs.values().last()->start();
    }
}

void UpdateE2eeFolderUsersMetadataJob::slotFolderLockedError(const QByteArray &folderId, int httpErrorCode)
{
    Q_UNUSED(httpErrorCode);
    qCDebug(lcUpdateE2eeFolderUsersMetadataJob) << "Folder" << folderId << "Couldn't be locked.";
    emit finished(404, tr("Could not lock a folder %1").arg(QString::fromUtf8(_folderId)));
}

}
