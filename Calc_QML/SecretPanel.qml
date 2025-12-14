import QtQuick 2.0
import QtQuick.Controls 2.12

Item {

    Rectangle
    {
        width: parent.width
        height: 100;
        color: "green"
        Text
        {
            id: secret
            text: "Секретное меню"
            color: "Black"

            font.family: openSansSemiBold.name
            font.pixelSize: 30
            lineHeight: 0.83  // =50/60
            font.letterSpacing: 0.5
            font.bold: true
        }

        Button {
            width: 150
            height: 50
            //left: (parent.width - width)/2
            //top: secret.height + 2

            text: "Назад"
            onClicked: {secPan.visible = false; secretCode = ""}


            background: Rectangle
            {
                color: "silver"
                radius: 5
                border.color: "#cccccc"
                border.width: 1
            }

            anchors
            {
                bottom: parent.bottom
                bottomMargin: 5
                left: parent.left
                leftMargin: (parent.width - width)/2
            }
        }
    }

}
