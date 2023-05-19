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

#include "owncloudpropagator.h"
#include "syncfileitem.h"

#include <QScopedPointer>

class QNetworkReply;

namespace OCC {

class FolderMetadata;

class OWNCLOUDSYNC_EXPORT UpdateE2eeFolderMetadataJob : public PropagatorJob
{
    Q_OBJECT

public:
    explicit UpdateE2eeFolderMetadataJob(OwncloudPropagator *propagator, const SyncFileItemPtr &item, const QString &encryptedRemotePath);

    bool scheduleSelfOrChild() override;

    [[nodiscard]] JobParallelism parallelism() const override;

private slots:
    void start();
    void slotFolderEncryptedIdReceived(const QStringList &list);
    void slotFolderEncryptedIdError(QNetworkReply *reply);
    void slotFolderLockedSuccessfully(const QByteArray &fileId, const QByteArray &token);
    void slotFolderLockedError(const QByteArray &fileId, int httpErrorCode);
    void slotTryLock(const QByteArray &fileId);
    void slotFolderEncryptedMetadataReceived(const QJsonDocument &json, int statusCode);
    void slotFolderEncryptedMetadataError(const QByteArray &fileId, int httpReturnCode);
    void slotUpdateMetadataSuccess(const QByteArray &fileId);
    void slotUpdateMetadataError(const QByteArray &fileId, int httpReturnCode);
    void unlockFolder(bool success);

signals:
    void fileDropMetadataParsedAndAdjusted(const OCC::FolderMetadata *const metadata);

private:
    SyncFileItemPtr _item;
    QString _encryptedRemotePath;
    bool _currentLockingInProgress = false;

    bool _isUnlockRunning = false;
    bool _isFolderLocked = false;
    
    QByteArray _folderToken;
    QByteArray _folderId;

    QScopedPointer<FolderMetadata> _metadata;
};

}
