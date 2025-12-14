import QtQuick 2.12
import QtQuick.Controls 2.12

Button {

    property int type: 1 // 1 - num; 2 - action; 3 - clear

    property color buttonColor:  type == 1 ? "#B0D1D8" : (type == 2 ? "#0889A6" : "#F25E5E")
    property color hoverColor:   type == 1 ? "#04BFAD" : (type == 2 ? "#F7E425" : "#F9AFAF")
//    property color pressedColor: type == 2 ? "#F7E425" : (type == 3 ? "#F7E425" : "#F7E425")

    property color textColor: (hovered || (type === 2) || (type === 3)) ? "white" : "#024875"

    background: Rectangle {
        implicitWidth: 60
        implicitHeight: 60
//        color: parent.down ? pressedColor : (parent.hovered ? hoverColor : buttonColor)
        color: parent.hovered ? hoverColor : buttonColor
        radius: 30
    }

    contentItem: Text {
        text: parent.text
        color: textColor

        font.family: openSansSemiBold.name
        font.pixelSize: 24
        lineHeight: 0.8  // =24/30
        font.letterSpacing: 1
        font.bold: true
        //anchors.horizontalCenter: parent.horizontalCenter

        horizontalAlignment: Text.AlignHCenter
        verticalAlignment: Text.AlignVCenter
    }
}
