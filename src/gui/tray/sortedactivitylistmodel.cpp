/*
 * Copyright (C) by Claudio Cambra <claudio.cambra@nextcloud.com>
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

#include "activitylistmodel.h"

#include "sortedactivitylistmodel.h"

namespace OCC {

SortedActivityListModel::SortedActivityListModel(QObject *parent)
    : QSortFilterProxyModel(parent)
{
}

void SortedActivityListModel::sortModel()
{
    sort(0);
}

ActivityListModel* SortedActivityListModel::activityListModel() const
{
    return dynamic_cast<ActivityListModel*>(sourceModel());
}

void SortedActivityListModel::setActivityListModel(ActivityListModel* activityListModel)
{
     if(const auto currentSetModel = sourceModel()) {
         disconnect(currentSetModel, &ActivityListModel::rowsInserted, this, &SortedActivityListModel::sortModel);
         disconnect(currentSetModel, &ActivityListModel::rowsMoved, this, &SortedActivityListModel::sortModel);
         disconnect(currentSetModel, &ActivityListModel::rowsRemoved, this, &SortedActivityListModel::sortModel);
         disconnect(currentSetModel, &ActivityListModel::dataChanged, this, &SortedActivityListModel::sortModel);
         disconnect(currentSetModel, &ActivityListModel::modelReset, this, &SortedActivityListModel::sortModel);
     }

     // Re-sort model when any changes take place
     connect(activityListModel, &ActivityListModel::rowsInserted, this, &SortedActivityListModel::sortModel);
     connect(activityListModel, &ActivityListModel::rowsMoved, this, &SortedActivityListModel::sortModel);
     connect(activityListModel, &ActivityListModel::rowsRemoved, this, &SortedActivityListModel::sortModel);
     connect(activityListModel, &ActivityListModel::dataChanged, this, &SortedActivityListModel::sortModel);
     connect(activityListModel, &ActivityListModel::modelReset, this, &SortedActivityListModel::sortModel);

    setSourceModel(activityListModel);
    Q_EMIT activityListModelChanged();
}

bool SortedActivityListModel::lessThan(const QModelIndex &sourceLeft, const QModelIndex &sourceRight) const
{
    if (!sourceLeft.isValid() || !sourceRight.isValid()) {
        return false;
    }

    const auto leftActivity = sourceLeft.data(ActivityListModel::ActivityRole).value<Activity>();
    const auto rightActivity = sourceRight.data(ActivityListModel::ActivityRole).value<Activity>();

    // First compare by general activity type
    const auto leftType = leftActivity._type;

    if (leftType == Activity::DummyFetchingActivityType) {
        // The fetching activities dummy activity always goes at the top
        return true;
    } else if (leftType == Activity::DummyMoreActivitiesAvailableType) {
        // Likewise the dummy "more activities available" activity always goes at the bottom
        return false;
    }

    // Let's now check for errors as we want those near the top too
    // Sync result errors go first
    const auto leftSyncResultStatus = leftActivity._syncResultStatus;
    const auto rightSyncResultStatus = rightActivity._syncResultStatus;

    const auto leftIsSyncResultError = leftSyncResultStatus == SyncResult::Error ||
                                       leftSyncResultStatus == SyncResult::SetupError ||
                                       leftSyncResultStatus == SyncResult::Problem;

    const auto rightIsSyncResultError = rightSyncResultStatus == SyncResult::Error ||
                                        rightSyncResultStatus == SyncResult::SetupError ||
                                        rightSyncResultStatus == SyncResult::Problem;

    if (leftIsSyncResultError != rightIsSyncResultError) {
        return leftIsSyncResultError;
    } // If they are both errors then we will order the errors according to enum order later

    // Then sync file item status errors
    const auto leftSyncFileItemStatus = leftActivity._syncFileItemStatus;
    const auto rightSyncFileItemStatus = rightActivity._syncFileItemStatus;
    const bool leftIsErrorFileItemStatus = leftSyncFileItemStatus == SyncFileItem::FatalError ||
                                           leftSyncFileItemStatus == SyncFileItem::SoftError ||
                                           leftSyncFileItemStatus == SyncFileItem::NormalError;

    const bool rightIsErrorFileItemStatus = rightSyncFileItemStatus == SyncFileItem::FatalError ||
                                            rightSyncFileItemStatus == SyncFileItem::SoftError ||
                                            rightSyncFileItemStatus == SyncFileItem::NormalError;

    if (leftIsErrorFileItemStatus != rightIsErrorFileItemStatus) {
        return leftIsErrorFileItemStatus;
    }

    if (const auto rightType = rightActivity._type; leftType != rightType) {
        return leftType < rightType;
    }

    if (leftSyncResultStatus != rightSyncResultStatus) {
        return leftSyncResultStatus != SyncResult::Undefined &&
                leftSyncResultStatus != SyncResult::Success;
    }

    if (leftSyncFileItemStatus != rightSyncFileItemStatus) {
        // We want to shove erors towards the top.
        return leftSyncFileItemStatus < rightSyncFileItemStatus;
    }

    // Finally sort by time, latest first
    const auto leftDateTime = leftActivity._dateTime;
    const auto rightDateTime = rightActivity._dateTime;

    return leftDateTime > rightDateTime;
}

}
