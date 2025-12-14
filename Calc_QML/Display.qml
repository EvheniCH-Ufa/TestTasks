import QtQuick 2.0

Item {

    property alias currText: currdisplayText.text
    property alias allText: alldisplayText.text

    property string allText: "368+497"
    property string currText: "865"

    Rectangle {
        id: currTextfield
        //anchors.centerIn: top
        width: parent.width
        height: 210
        y: -30
        color: "#04bfad"
        radius: 25

        Text {
            id: currdisplayText
            text: currText
            color: "white"

            font.family: openSansSemiBold.name
            font.pixelSize: 50
            lineHeight: 0.83  // =50/60
            font.letterSpacing: 0.5
            font.bold: true
            anchors
            {
                right: parent.right
                bottom: parent.bottom
                margins: 25
            }
        }

        Text {
            id : alldisplayText
            text: allText
            color: "white"

            font.family: openSansSemiBold.name
            font.pixelSize: 20
            lineHeight: 1.5  // =20/30
            font.letterSpacing: 0.5
            font.bold: false
            anchors
            {
                right: parent.right
                bottom: parent.bottom
                rightMargin : 25
                bottomMargin : 70
            }
        }


    }


/*
    Rectangle {
        id: allTextfield
            anchors.centerIn: top
            width: parent.width
            height: 115
            color: "#04bfad"



    }

*/


}
