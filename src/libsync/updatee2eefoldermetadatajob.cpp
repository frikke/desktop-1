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

#include "updatee2eefoldermetadatajob.h"

#include "account.h"
#include "clientsideencryptionjobs.h"
#include "clientsideencryption.h"
#include "foldermetadata.h"

#include <QLoggingCategory>
#include <QNetworkReply>

namespace OCC {

Q_LOGGING_CATEGORY(lcUpdateFileDropMetadataJob, "nextcloud.sync.propagator.updatee2eefoldermetadatajob", QtInfoMsg)

}

namespace OCC {

UpdateE2eeFolderMetadataJob::UpdateE2eeFolderMetadataJob(OwncloudPropagator *propagator, const SyncFileItemPtr &item, const QString &encryptedRemotePath)
    : PropagatorJob(propagator),
    _item(item),
    _encryptedRemotePath(encryptedRemotePath)
{
}

void UpdateE2eeFolderMetadataJob::start()
{
    Q_ASSERT(_item);
    qCDebug(lcUpdateFileDropMetadataJob) << "Folder is encrypted, let's get the Id from it.";
    const auto fetchFolderEncryptedIdJob = new LsColJob(propagator()->account(), _encryptedRemotePath, this);
    fetchFolderEncryptedIdJob->setProperties({"resourcetype", "http://owncloud.org/ns:fileid"});
    connect(fetchFolderEncryptedIdJob, &LsColJob::directoryListingSubfolders, this, &UpdateE2eeFolderMetadataJob::slotFolderEncryptedIdReceived);
    connect(fetchFolderEncryptedIdJob, &LsColJob::finishedWithError, this, &UpdateE2eeFolderMetadataJob::slotFolderEncryptedIdError);
    fetchFolderEncryptedIdJob->start();
}

bool UpdateE2eeFolderMetadataJob::scheduleSelfOrChild()
{
    if (_state == Finished) {
        return false;
    }

    if (_state == NotYetStarted) {
        _state = Running;
        start();
    }

    return true;
}

PropagatorJob::JobParallelism UpdateE2eeFolderMetadataJob::parallelism() const
{
    return PropagatorJob::JobParallelism::WaitForFinished;
}

void UpdateE2eeFolderMetadataJob::slotFolderEncryptedIdReceived(const QStringList &list)
{
    qCDebug(lcUpdateFileDropMetadataJob) << "Received id of folder, trying to lock it so we can prepare the metadata";
    const auto fetchFolderEncryptedIdJob = qobject_cast<LsColJob *>(sender());
    Q_ASSERT(fetchFolderEncryptedIdJob);
    if (!fetchFolderEncryptedIdJob) {
        qCCritical(lcUpdateFileDropMetadataJob) << "slotFolderEncryptedIdReceived must be called by a signal";
        _item->_errorString = tr("Failed to update folder metadata.");
        finished(SyncFileItem::FatalError);
        return;
    }
    Q_ASSERT(!list.isEmpty());
    if (list.isEmpty()) {
        qCCritical(lcUpdateFileDropMetadataJob) << "slotFolderEncryptedIdReceived list.isEmpty()";
        _item->_errorString = tr("Failed to update folder metadata.");
        finished(SyncFileItem::FatalError);
        return;
    }
    const auto &folderInfo = fetchFolderEncryptedIdJob->_folderInfos.value(list.first());
    slotTryLock(folderInfo.fileId);
}

void UpdateE2eeFolderMetadataJob::slotTryLock(const QByteArray &fileId)
{
    const auto lockJob = new LockEncryptFolderApiJob(propagator()->account(), fileId, propagator()->_journal, propagator()->account()->e2e()->_publicKey, this);
    connect(lockJob, &LockEncryptFolderApiJob::success, this, &UpdateE2eeFolderMetadataJob::slotFolderLockedSuccessfully);
    connect(lockJob, &LockEncryptFolderApiJob::error, this, &UpdateE2eeFolderMetadataJob::slotFolderLockedError);
    lockJob->start();
}

void UpdateE2eeFolderMetadataJob::slotFolderLockedSuccessfully(const QByteArray &fileId, const QByteArray &token)
{
    qCDebug(lcUpdateFileDropMetadataJob) << "Folder" << fileId << "Locked Successfully for Upload, Fetching Metadata"; 
    _folderToken = token;
    _folderId = fileId;
    _isFolderLocked = true;

    const auto fetchMetadataJob = new GetMetadataApiJob(propagator()->account(), _folderId);
    connect(fetchMetadataJob, &GetMetadataApiJob::jsonReceived, this, &UpdateE2eeFolderMetadataJob::slotFolderEncryptedMetadataReceived);
    connect(fetchMetadataJob, &GetMetadataApiJob::error, this, &UpdateE2eeFolderMetadataJob::slotFolderEncryptedMetadataError);

    fetchMetadataJob->start();
}

void UpdateE2eeFolderMetadataJob::slotFolderEncryptedMetadataError(const QByteArray &fileId, int httpReturnCode)
{
    Q_UNUSED(fileId);
    Q_UNUSED(httpReturnCode);
    qCDebug(lcUpdateFileDropMetadataJob()) << "Error Getting the encrypted metadata. Pretend we got empty metadata.";
    slotFolderEncryptedMetadataReceived({}, httpReturnCode);
}

void UpdateE2eeFolderMetadataJob::slotFolderEncryptedMetadataReceived(const QJsonDocument &json, int statusCode)
{
    qCDebug(lcUpdateFileDropMetadataJob) << "Metadata Received, Preparing it for the new file." << json.toVariant();
    // Encrypt File!
    SyncJournalFileRecord rec;
    if (!propagator()->_journal->getRootE2eFolderRecord(_encryptedRemotePath, &rec) || !rec.isValid()) {
        unlockFolder(false);
        return;
    }

    _metadata.reset(new FolderMetadata(
        propagator()->account(),
        statusCode == 404 ? QByteArray{} : json.toJson(QJsonDocument::Compact),
        FolderMetadata::RootEncryptedFolderInfo(FolderMetadata::RootEncryptedFolderInfo::createRootPath(rec.path(), _encryptedRemotePath)))
    );
    connect(_metadata.data(), &FolderMetadata::setupComplete, this, [this] {
        if (!_metadata->isValid() || (!_metadata->moveFromFileDropToFiles() && !_metadata->encryptedMetadataNeedUpdate())) {
            unlockFolder(false);
            return;
        }

        emit fileDropMetadataParsedAndAdjusted(_metadata.data());

        const auto updateMetadataJob = new UpdateMetadataApiJob(propagator()->account(), _folderId, _metadata->encryptedMetadata(), _folderToken);
        connect(updateMetadataJob, &UpdateMetadataApiJob::success, this, &UpdateE2eeFolderMetadataJob::slotUpdateMetadataSuccess);
        connect(updateMetadataJob, &UpdateMetadataApiJob::error, this, &UpdateE2eeFolderMetadataJob::slotUpdateMetadataError);
        updateMetadataJob->start();
    });
}

void UpdateE2eeFolderMetadataJob::slotUpdateMetadataSuccess(const QByteArray &fileId)
{
    Q_UNUSED(fileId);
    qCDebug(lcUpdateFileDropMetadataJob) << "Uploading of the metadata success, Encrypting the file";

    qCDebug(lcUpdateFileDropMetadataJob) << "Finalizing the upload part, now the actuall uploader will take over";
    unlockFolder(true);
}

void UpdateE2eeFolderMetadataJob::slotUpdateMetadataError(const QByteArray &fileId, int httpErrorResponse)
{
    qCDebug(lcUpdateFileDropMetadataJob) << "Update metadata error for folder" << fileId << "with error" << httpErrorResponse;
    qCDebug(lcUpdateFileDropMetadataJob()) << "Unlocking the folder.";
    unlockFolder(false);
}

void UpdateE2eeFolderMetadataJob::slotFolderLockedError(const QByteArray &fileId, int httpErrorCode)
{
    Q_UNUSED(httpErrorCode);
    qCDebug(lcUpdateFileDropMetadataJob) << "Folder" << fileId << "with path" << _encryptedRemotePath << "Coundn't be locked. httpErrorCode" << httpErrorCode;
    _item->_errorString = tr("Failed to lock encrypted folder.");
    finished(SyncFileItem::NormalError);
}

void UpdateE2eeFolderMetadataJob::slotFolderEncryptedIdError(QNetworkReply *reply)
{
    if (!reply) {
        qCDebug(lcUpdateFileDropMetadataJob) << "Error retrieving the Id of the encrypted folder" << _encryptedRemotePath;
    } else {
        qCDebug(lcUpdateFileDropMetadataJob) << "Error retrieving the Id of the encrypted folder" << _encryptedRemotePath << "with httpErrorCode" << reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    }
    _item->_errorString = tr("Failed to update folder metadata.");
    finished(SyncFileItem::NormalError);
}

void UpdateE2eeFolderMetadataJob::unlockFolder(bool success)
{
    Q_ASSERT(!_isUnlockRunning);
    Q_ASSERT(_item);

    if (_isUnlockRunning) {
        qCWarning(lcUpdateFileDropMetadataJob) << "Double-call to unlockFolder.";
        return;
    }

    if (!success) {
        _item->_errorString = tr("Failed to update folder metadata.");
    }

    const auto itemStatus = success ? SyncFileItem::Success : SyncFileItem::FatalError;

    if (!_isFolderLocked) {
        if (success) {
            _item->_e2eEncryptionStatus = _metadata->encryptedMetadataEncryptionStatus();
        }
        finished(itemStatus);
        return;
    }

    _isUnlockRunning = true;

    qCDebug(lcUpdateFileDropMetadataJob) << "Calling Unlock";
    const auto unlockJob = new UnlockEncryptFolderApiJob(propagator()->account(), _folderId, _folderToken, propagator()->_journal, this);

    connect(unlockJob, &UnlockEncryptFolderApiJob::success, [this](const QByteArray &folderId) {
        qCDebug(lcUpdateFileDropMetadataJob) << "Successfully Unlocked";
        _folderToken.clear();
        _folderId.clear();
        _isFolderLocked = false;

        _item->_e2eEncryptionStatus = _metadata->encryptedMetadataEncryptionStatus();
        _item->_e2eEncryptionStatusRemote = _metadata->encryptedMetadataEncryptionStatus();

        _isUnlockRunning = false;
        finished(SyncFileItem::Success);
    });
    connect(unlockJob, &UnlockEncryptFolderApiJob::error, [this](const QByteArray &folderId, int httpStatus) {
        qCDebug(lcUpdateFileDropMetadataJob) << "Unlock Error";

        _isUnlockRunning = false;
        _item->_errorString = tr("Failed to unlock encrypted folder.");
        finished(SyncFileItem::FatalError);
    });
    unlockJob->start();
}


}
