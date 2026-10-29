/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * This wraps the Breeze theme and overlays a progress indicator on
 * top of it.
 */

import QtQuick

Item {
    // Load the stock Breeze theme.
    Loader {
        anchors.fill: parent
        source: "file:///usr/share/sddm/themes/breeze/Main.qml"
    }

    // Put the progress indicator on top, at a fixed distance below
    // the vertical center. This should appear between the password
    // entry and the Sleep, Restart, etc. buttons at any resolution.
    ProgressIndicator {
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.top: parent.verticalCenter
        anchors.topMargin: 150
    }
}
