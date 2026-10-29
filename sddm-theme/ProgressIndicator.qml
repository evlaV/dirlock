/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Shows progress information on the SDDM greeter.
 */

import QtQuick

Item {
    id: root

    /*
     * JSON state file written by dirlock-sddm-tracker, format:
     *   {"active": true, "percent": 42, "label": "Encrypting data"}
     * If "percent" is missing or < 0, only the label is shown.
     * If "active" is false the indicator is hidden.
     */
    property string stateFile: "/run/dirlock-progress/state.json"

    // Parsed state
    property bool active: false
    property int percent: -1
    property string label: ""

    implicitWidth: Math.max(320, labelText.implicitWidth + 40)
    implicitHeight: column.implicitHeight + 28

    visible: active

    function refresh() {
        const xhr = new XMLHttpRequest();
        xhr.onreadystatechange = function() {
            if (xhr.readyState !== XMLHttpRequest.DONE) {
                return;
            }
            // An empty or missing file means that there is nothing to show
            if (!xhr.responseText) {
                root.active = false;
                return;
            }
            try {
                const d = JSON.parse(xhr.responseText);
                root.label = d.label ?? "";
                root.percent = d.percent ?? -1;
                root.active = d.active !== false;
            } catch (e) {
                console.warn("ProgressIndicator: malformed state file:", e);
                root.active = false;
            }
        };
        xhr.open("GET", "file://" + root.stateFile);
        xhr.send();
    }

    Timer {
        interval: 1000
        running: true
        repeat: true
        triggeredOnStart: true
        onTriggered: root.refresh()
    }

    Rectangle {
        anchors.fill: parent
        radius: 10
        color: Qt.rgba(0, 0, 0, 0.55)

        Column {
            id: column

            anchors.centerIn: parent
            width: parent.width - 40
            spacing: 10

            Text {
                id: labelText

                anchors.horizontalCenter: parent.horizontalCenter
                color: "white"
                font.pixelSize: 16
                text: root.label
            }

            Rectangle {
                visible: root.percent >= 0
                width: parent.width
                height: 6
                radius: 3
                color: Qt.rgba(1, 1, 1, 0.25)

                Rectangle {
                    height: parent.height
                    radius: parent.radius
                    color: "#3daee9"
                    width: parent.width * Math.max(0, root.percent) / 100
                    Behavior on width {
                        NumberAnimation { duration: 200 }
                    }
                }
            }

            Text {
                anchors.horizontalCenter: parent.horizontalCenter
                visible: root.percent >= 0
                color: "white"
                font.pixelSize: 12
                text: root.percent + "%"
            }
        }
    }
}
