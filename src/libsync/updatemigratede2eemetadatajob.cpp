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

#include "updatemigratede2eemetadatajob.h"

#include "updatee2eefolderusersmetadatajob.h"

#include "account.h"
#include "clientsideencryptionjobs.h"
#include "clientsideencryption.h"
#include "foldermetadata.h"
#include "syncfileitem.h"

#include <QLoggingCategory>
#include <QNetworkReply>
#include <QSslCertificate>

namespace OCC {

Q_LOGGING_CATEGORY(lcUpdateMigratedE2eeMetadataJob, "nextcloud.sync.propagator.updatemigratede2eemetadatajob", QtInfoMsg)

}

namespace OCC {

UpdateMigratedE2eeMetadataJob::UpdateMigratedE2eeMetadataJob(OwncloudPropagator *propagator,
                                                             const QString &path,
                                                             const QString &folderRemotePath)
    : PropagatorJob(propagator)
    , _path(path)
    , _folderRemotePath(folderRemotePath)
{
}

void UpdateMigratedE2eeMetadataJob::start()
{
    qDebug() << "Folder is encrypted, let's get the Id from it.";
    const auto pathSanitized = _path.startsWith(QLatin1Char('/')) ? _path.mid(1) : _path;
    const auto fetchFolderEncryptedIdJob = new LsColJob(propagator()->account(), _folderRemotePath + pathSanitized, this);
    fetchFolderEncryptedIdJob->setProperties({"resourcetype", "http://owncloud.org/ns:fileid"});
    connect(fetchFolderEncryptedIdJob, &LsColJob::directoryListingSubfolders, this, &UpdateMigratedE2eeMetadataJob::slotFolderEncryptedIdReceived);
    connect(fetchFolderEncryptedIdJob, &LsColJob::finishedWithError, this, &UpdateMigratedE2eeMetadataJob::slotFolderEncryptedIdError);
    fetchFolderEncryptedIdJob->start();
}

void UpdateMigratedE2eeMetadataJob::startUpdateFolderUsersMetadataJob(const QByteArray &folderId)
{
    const auto updateMedatadaAndSubfoldersJob = new UpdateE2eeFolderUsersMetadataJob(propagator()->account(),
                                                                                     propagator()->_journal,
                                                                                     folderId,
                                                                                     _folderRemotePath,
                                                                                     UpdateE2eeFolderUsersMetadataJob::Add,
                                                                                     _path,
                                                                                     propagator()->account()->davUser(),
                                                                                     propagator()->account()->e2e()->_certificate);
    updateMedatadaAndSubfoldersJob->setParent(this);
    updateMedatadaAndSubfoldersJob->start();
    connect(updateMedatadaAndSubfoldersJob, &UpdateE2eeFolderUsersMetadataJob::finished, this, [this]() {
        emit finished(SyncFileItem::Status::Success);
    });
}

void UpdateMigratedE2eeMetadataJob::slotFolderEncryptedIdReceived(const QStringList &list)
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
    startUpdateFolderUsersMetadataJob(folderInfo.fileId);
}

void UpdateMigratedE2eeMetadataJob::slotFolderEncryptedIdError(QNetworkReply *r)
{
    Q_UNUSED(r);
    qCritical() << "Error retrieving the Id of the encrypted folder.";
    emit finished(SyncFileItem::Status::FatalError);
}

bool UpdateMigratedE2eeMetadataJob::scheduleSelfOrChild()
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

PropagatorJob::JobParallelism UpdateMigratedE2eeMetadataJob::parallelism() const
{
    return PropagatorJob::JobParallelism::WaitForFinished;
}
}
