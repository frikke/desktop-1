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

#pragma once


#include "account.h"
#include "gui/sharemanager.h"
#include "syncfileitem.h"
#include "gui/sharee.h"

#include <QHash>
#include <QMutex>
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

    struct UserData {
        ShareePtr sharee;
        Share::Permissions desiredPermissions;
        QString password;
    };

    explicit UpdateE2eeFolderUsersMetadataJob(const AccountPtr &account,
                                        SyncJournalDb *journalDb,
                                        const QString &syncFolderRemotePath,
                                        const Operation operation,
                                        const QString &path = {},
                                        const QString &folderUserId = {},
                                        QSslCertificate certificate = QSslCertificate{},
                                        QObject *parent = nullptr);

public:
    [[nodiscard]] QString path() const;
    [[nodiscard]] UserData userData() const;
    [[nodiscard]] SyncFileItem::EncryptionStatus encryptionStatus() const;

public slots:
    void start();
    void startUpdate();
    void setUserData(const UserData &userData);
    void setFolderToken(const QByteArray &folderToken);
    void setMetadataKeyForEncryption(const QByteArray &metadataKey);
    void setMetadataKeyForDecryption(const QByteArray &metadataKey);
    void setKeyChecksums(const QSet<QByteArray> &keyChecksums);

    void setJubJobItems(const QHash<QString, SyncFileItemPtr> &subJobItems);

private slots:
    void slotCertificatesFetchedFromServer(const QHash<QString, QSslCertificate> &results);
    void slotCertificateFetchedFromKeychain(const QSslCertificate certificate);
    void slotCertificateReady();
    void slotFetchFolderMetadata();
    void slotFolderEncryptedIdReceived(const QStringList &list);
    void slotFolderEncryptedIdError(QNetworkReply *reply);
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
    QByteArray _metadataKeyForEncryption;
    QByteArray _metadataKeyForDecryption;
    QSet<QByteArray> _keyChecksums;
    QSharedPointer<FolderMetadata> _folderMetadata;
    QSet<UpdateE2eeFolderUsersMetadataJob *> _subJobs;
    UserData _userData;
    QHash<QString, SyncFileItemPtr> _subJobItems;
    QMutex _subjobItemsMutex;
};

}
