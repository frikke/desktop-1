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

#pragma once


#include "account.h"
#include "gui/sharemanager.h"

#include <QHash>
#include <QObject>
#include <QSslCertificate>
#include <QString>

namespace OCC {
class FolderMetadata;
class SyncJournalDb;
class OWNCLOUDSYNC_EXPORT UpdateE2eeFolderUsersMetadataJob : public QObject
{
    Q_OBJECT

public:
    enum Operation { Invalid = -1, Add = 0, Remove, ReEncrypt };
    explicit UpdateE2eeFolderUsersMetadataJob(const AccountPtr &account,
                                        SyncJournalDb *journalDb,
                                        const QByteArray &folderId,
                                        const QString &syncFolderRemotePath,
                                        const Operation operation,
                                        const QString &path = {},
                                        const QString &folderUserId = {},
                                        QSslCertificate certificate = QSslCertificate{},
                                        QObject *parent = nullptr);

public:
    [[nodiscard]] QString path() const;
    [[nodiscard]] QVariant userData() const;

public slots:
    void start();
    void setUserData(const QVariant &userData);
    void setTopLevelFolderMetadata(const QSharedPointer<FolderMetadata> &topLevelFolderMetadata);
    void setFolderToken(const QByteArray &folderToken);
    void setMetadataKeyForDecryption(const QByteArray &metadataKey);

private slots:
    void slotCertificatesFetchedFromServer(const QHash<QString, QSslCertificate> &results);
    void slotCertificateFetchedFromKeychain(const QSslCertificate certificate);
    void slotCertificateReady();
    void slotFetchFolderMetadata();
    void slotMetadataReceived(const QJsonDocument &json, int statusCode);
    void slotMetadataError(const QByteArray &folderId, int httpReturnCode);
    void slotScheduleSubJobs();
    void slotFolderLockedSuccessfully(const QByteArray &folderId, const QByteArray &token);
    void slotFolderLockedError(const QByteArray &folderId, int httpErrorCode);
    void slotLockFolder();
    void slotUnlockFolder();
    void slotUpdateMetadataSuccess(const QByteArray &folderId);
    void slotUpdateMetadataError(const QByteArray &folderId, int httpReturnCode);
    void slotFolderUnlocked(const QByteArray &folderId, int httpStatus);
    void slotUpdateFolderMetadata();
    void slotSubJobsFinished();
    void slotSubJobFinished(int code, const QString &message = {});

private: signals:
    void certificateReady();
    void finished(int code, const QString &message = {});

private:
    AccountPtr _account;
    QPointer<SyncJournalDb> _journalDb;
    QByteArray _folderId;
    QString _syncFolderRemotePath;
    Operation _operation;
    QString _path;
    QString _folderUserId;
    QSslCertificate _folderUserCertificate;
    QByteArray _folderToken;
    QByteArray _metadataKeyForDecryption;
    QSharedPointer<FolderMetadata> _folderMetadata;
    QSet<UpdateE2eeFolderUsersMetadataJob *> _subJobs;
    QSharedPointer<FolderMetadata> _topLevelFolderMetadata;
    QVariant _userData;
};

}
