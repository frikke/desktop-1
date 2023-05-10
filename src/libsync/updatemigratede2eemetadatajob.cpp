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

#include "gui/updatee2eesharemetadatajob.h"
#include "gui/folderman.h"

#include "account.h"
#include "gui/accountstate.h"
#include "clientsideencryptionjobs.h"
#include "clientsideencryption.h"
#include "foldermetadata.h"
#include "syncfileitem.h"

#include <QLoggingCategory>
#include <QNetworkReply>

namespace OCC {

Q_LOGGING_CATEGORY(lcUpdateMigratedE2eeMetadataJob, "nextcloud.sync.propagator.updatemigratede2eemetadatajob", QtInfoMsg)

}

namespace OCC {

UpdateMigratedE2eeMetadataJob::UpdateMigratedE2eeMetadataJob(OwncloudPropagator *propagator, const QByteArray &folderId, const QString &path)
    : PropagatorJob(propagator)
    , _folderId(folderId)
    , _path(path)
{
}

void UpdateMigratedE2eeMetadataJob::start()
{
    const auto account = propagator()->account();
    QString folderAlias;
    for (const auto &f : FolderMan::instance()->map()) {
        if (f->accountState()->account() != account) {
            continue;
        }
        const auto folderPath = f->remotePath();
        if (_path.startsWith(folderPath) && (_path == folderPath || folderPath.endsWith('/') || _path[folderPath.size()] == '/')) {
            folderAlias = f->alias();
        }
    }

    const auto updateMedatadaAndSubfoldersJob = new UpdateE2eeShareMetadataJob(propagator()->account(),
                                                                               _folderId,
                                                                               folderAlias,
                                                                               propagator()->account()->davUser(),
                                                                               UpdateE2eeShareMetadataJob::Add,
                                                                               _path);
    updateMedatadaAndSubfoldersJob->setParent(this);
    updateMedatadaAndSubfoldersJob->start();
    connect(updateMedatadaAndSubfoldersJob, &UpdateE2eeShareMetadataJob::finished, this, [this]() {
        emit finished(SyncFileItem::Status::Success);
    });
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
