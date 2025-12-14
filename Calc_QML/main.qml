import QtQuick 2.12
import QtQuick.Window 2.12
import QtQuick.Controls 2.12

/*

Александр
Собеседование
Евгений, здравствуйте!

Благодарим Вас за отклик на вакансию "Программист C++/QML".

Ваше резюме показалось нам очень интересным.
Мы хотели бы пригласить Вас на интервью, но для экономии Вашего времени просим выполнить небольшое тестовое задание
Необходимо написать приложение калькулятор (самое простое) со скрытыми меню:

Точь в точь по прототипу:
https://www.figma.com/file/gJIvIUNBfA1OqMXshPFocu/Calculator_Android?node-id=0%3A1
• Необходимые функции (сложение, вычитания т.п.) отображены на изображение.
• Возможность операций с числами до 25 знаков.
• При долгом нажатие (4 секунды) на =, а после (в течение 5 секунд) ввода комбинации «123» должен открыться 2 экран с одной надписью “Секретное меню” и кнопкой назад
Среда разработки qt, технологии qml для графики!

Рудаков Александр


Общая схема работы:
Все цифры и знаки пишем, включая проценты.

очередность применения словарей:
- %;
- * или /
- + или -
Затем решаем. Меняем видимую часть.

Прроценты меняем следующим образом при парсинге:
х% -> x/100;
... *x% -> *x/100
... /x% -> /x*100
... +x% -> *(1 + x/100)
... -x% -> *(1 - x/100)

кнопка номер:
- если последняя номер - дописываем
- если последняя действие - пишем новое число

Кнопка действие:
- если последняя число, то фиксируем действие
- если последняя действие, то меняем

Кнопка процент, то пишем процент и ставим плюс
- если последняя число, то пишем %
- если последняя действие, то ничего


*/


Window
{
    id: mainWindow
    width: 360
    height: 640
    visible: true
    title: "Калькулятор"

    FontLoader
	{
		id: openSansSemiBold
		source: "qrc:/fonts/Open_Sans.ttf"
	}

    property string currentInput: "0"
    property string allInput: "0"
    property bool   isDouble: false
    property string lastAction: ""
    property int    skobki_count: 0
//    property bool   last_oper_is_digit: false
    property string   last_operation: ""
    property bool   secretCodeActive: false
    property string secretCode: ""

    property var   calcResult: {0; 0}


    Rectangle
    {
        //anchors.centerIn: bottom
        width: parent.width
        height: parent.height
        color: "#024875"

		Display
		{
			id: basicDisplay
			width: parent.width
			height: 180
			currText: currentInput
			allText: allInput
		}

		Grid
		{
		   id: gridLayout
		   y: 280
		   anchors.centerIn: parent
		   anchors.verticalCenterOffset: 80
		   columns: 4
		   rows: 5
		   spacing: 20

		   //1
		   NumberButton {text: "( )";  type: 2; onClicked: skobki()}
		   NumberButton {text: "+/-";  type: 2; onClicked: plusORminus()}
		   NumberButton {text: "%";    type: 2; onClicked: percent()}
           NumberButton {text: "÷";    type: 2; onClicked: runAction("/")}

		   //2
		   NumberButton {text: "7"; type: 1; onClicked: addDigit(7)}
		   NumberButton {text: "8"; type: 1; onClicked: addDigit(8)}
		   NumberButton {text: "9"; type: 1; onClicked: addDigit(9)}

           NumberButton {text: "×"; type: 2; onClicked: runAction("*")}

		   //3
		   NumberButton {text: "4"; type: 1; onClicked: addDigit(4)}
		   NumberButton {text: "5"; type: 1; onClicked: addDigit(5)}
		   NumberButton {text: "6"; type: 1; onClicked: addDigit(6)}

           NumberButton {text: "–"; type: 2; onClicked: runAction("-")}

		   //4
		   NumberButton {text: "1"; type: 1; onClicked: addDigit(1)}
		   NumberButton {text: "2"; type: 1; onClicked: addDigit(2)}
		   NumberButton {text: "3"; type: 1; onClicked: addDigit(3)}

           NumberButton {text: "+"; type: 2; onClicked: runAction("+")}

		   //5
		   NumberButton {text: "С"; type: 3; onClicked: clearAll()}
		   NumberButton {text: "0"; type: 1; onClicked: addDigit(0)}
		   NumberButton {text: "."; type: 1; onClicked: addDigit(999)}
		   NumberButton {text: "="; type: 2; onClicked: calculate()
											 onPressed: startSecretCodeTimer()
											 onReleased: stopSecretCodeTimer()}
		}
    }

	SecretPanel
	{
		id: secPan
		y: 280
		width: parent.width
		height: 100
		visible: false
		z: 1
	}

	// Таймеры для секретного кода
	Timer
	{
		id: secretCodeTimer
		interval: 4000
		onTriggered: secretCodeTimerTriggered()
	}

	Timer
	{
		id: secretCodeTimerInput
		interval: 5000
		onTriggered: secretCodeTimerInputTriggered()
	}

	function startSecretCodeTimer()
	{
		secretCodeTimer.start()
        //console.log("secretCodeTimer.start()")
	}

	function secretCodeTimerTriggered()
	{
        //console.log("secretCodeActive = true")
		secretCodeActive = true
		secretCodeTimerInput.start()
	}

	function stopSecretCodeTimer()
	{
        //console.log("secretCodeTimer.stop()")
		if (secretCodeTimer.running)
		{
			secretCodeTimer.stop()
		}

		if (secretCodeActive === false)
		{

		}
	}


	function secretCodeTimerInputTriggered()
	{
        //console.log("timeout---------")
		secretCodeActive = false
		secretCodeTimerInput.stop()
		secretCodeTimer.stop()
		secretCode = ""
	}

    function formulaCalculate(formula_str)
	{
		// tut iz letcode kusok

         return calcRec("("+ formula_str + ")",0)

        //return 0.0
	}


    function calculate()
    {
        if (skobki_count > 0)
        {
            return
        }

        if (lastAction === "")
        {
            return
        }



        if (last_operation === ")" && skobki_count === 0)
        {
            //allInput = allInput.substring(0, allInput.length - 1)
        }
        else if (last_operation === "9")
        {
            allInput += currentInput
        }
        else if (last_operation === "+")
        {
            allInput = allInput.substring(0, allInput.length - 1)
        }
        else
        {
            return
        }

   /*     if (last_oper_is_digit === false)
        {
            if (allInput.substring(allInput.length - 1, allInput.length) !== ")")
            {
                allInput = allInput.substring(0, allInput.length - 1)
            }
        }
        else
        {
            allInput += currentInput
        }*/


        last_operation = ""

        //console.log("calcResult" )
        calcResult = formulaCalculate(scobkiFormula(allInput))
        //console.log("calcResult =" + calcResult.result_res)

        currentInput = calcResult.result_res

        lastAction = ""
        last_operation = ""
    }


    function skobki()
    {
        console.log(last_operation)
        if(last_operation === "" || last_operation === "(" || last_operation === "+")
        {
            if (allInput === "0")
            {
                allInput = ""
            }

            allInput = allInput + "("
            currentInput = "0"
            ++skobki_count
            last_operation = "("
            lastAction = "("
        }
        else // number or )
        {
            if (skobki_count === 0)
            {
                return
            }

            allInput += currentInput + ")"
            currentInput = "0"
            --skobki_count
            last_operation = ")"
        }
    }


    function percent()
    {
        /*
        Кнопка процент, то пишем процент и ставим плюс
        - если последняя число, то пишем %
        - если последняя действие, то ничего
        */

        if((last_operation === ")" || last_operation === "9") && allInput.length > 0 && currentInput !== "0")
        {
           /* allInput = allInput.substring(0, allInput.length) + currentInput + "%+";
            last_oper_is_digit = false
            currentInput = "0"
            lastAction = "+"*/


           var dop_str = ""
            switch (lastAction)
            {
               case "+": dop_str = "*(1+" + currentInput + "/100)"; break
               case "-": dop_str = "*(1-" + currentInput + "/100)"; break
               case "*": dop_str = "*(" + currentInput + "/100)"; break
               case "/": dop_str = "*(100/" + currentInput + ")"; break
            }
            allInput = allInput.substring(0, allInput.length -1) + dop_str;
        }
        last_operation = ")"
        currentInput = "0"
        lastAction = "+"
    }

    function plusORminus()
    {
        if (currentInput.substring(0,1) === "-")
        {
            currentInput = currentInput.substring(1, currentInput.length)
        }
        else
        {
            currentInput = "-" + currentInput
        }
    }

    // "C" = 0, "+" = 1, "-" = 2, "*" = 3, "/" = 4, "%" = 5, "+/-" = 6, "()" = 7, "=" = 9
    function runAction(action)
    {
        if (lastAction === "" && currentInput === "0")
        {
            return
        }

        if (lastAction === "" && currentInput !== "0")
        {
            allInput = currentInput
            currentInput = "0"
        }

//---------------------------------
        if (last_operation === "+")
        {
            allInput = allInput.substring(0, allInput.length - 1)
        }

        last_operation = "+"

        if (currentInput === "0")
        {
            currentInput = ""
        }

        if(allInput === "0")
        {
            allInput = ""
            calcResult = parseFloat(currentInput)
        }

        lastAction = action
        allInput += currentInput + lastAction

        currentInput = "0"
        return
    }


    function addDigit(num)
    {
        console.log("1 all_input = " + allInput)


        if(secretCodeActive === true && num < 4 )
        {
            //console.log("secretCode = " + num)

            secretCode += num
            if (secretCode === "123")
            {
                secPan.visible = true
            }
            //console.log("secretCode = " + secretCode)

            return
        }

        console.log("2 all_input = " + allInput)
        if (last_operation === ")")
        {
            return
        }

        last_operation = "9"

        console.log("3 all_input = " + allInput)
        if (num === 999)
        {
            if (isDouble === false)
            {
            currentInput += "."
            isDouble = true
            }
            return
        }

        console.log("4 all_input = " + allInput)

        if(lastAction === "")
        {
            console.log("las action empty")
      //      if (allInput === "")
     //       {
                allInput = "0"//currentInput
       //     }

            currentInput = ""
            lastAction = "-1"
        }

        console.log("5 all_input = " + allInput)

        if(currentInput === "0")
        {
            currentInput = ""
        }
        currentInput += num

        console.log("6 all_input = " + allInput)
    }


    function clearAll()
    {
        allInput = ""
        currentInput = "0"
        lastAction = -1
        calcResult = 0
        skobki_count = 0
    }


    function numberDetection(literalString)
    {
        switch(literalString)
        {
        case "0": return 0;
        case "1": return 1;
        case "2": return 2;
        case "3": return 3;
        case "4": return 4;
        case "5": return 5;
        case "6": return 6;
        case "7": return 7;
        case "8": return 8;
        case "9": return 9;
        case ".": return 10;
        default : return -1;
        }
    }

    function isNumber(symbol)
    {
        if ((symbol >= '0' && symbol <= '9') || symbol === '.')
        {
            return true
        }
        return false
    }

    function isScobka(symbol)
    {
        if (symbol === ')' || symbol === '(')
        {
            return true
        }
        return false
    }

   /*
    Варианты знаков:
    1. " )+5 " - влево до '(' вправо до не '5'
    2. " 5+( " - влево до не '5' вправо не ')'
    3. " 5+5 " - влево до не '5' вправо до не '5'
    4. " )+( " - влево до '(' вправо до ')'

    Обобщенно зависит от того, что попалось:
    - если число, то бежим до конца числа
    - если какая-то скобка, то до противоположной скобки
    */

    function probegNazad(formulaString, pos)
    {
        //console.log("in function probegNazad")
        //console.log(formulaString[pos])

        if (isNumber(formulaString[pos]))
        {
            //console.log(formulaString[pos] + " number is " + isNumber(formulaString[pos]))
            while(isNumber(formulaString[pos]))
            {
                --pos
            }
        }
        else if (formulaString[pos] === ')')
        {
            //console.log(formulaString[pos] + " scobki is " + isNumber(formulaString[pos]))
            while(formulaString[pos] !== '(')
            {
                --pos
            }
        }
        return pos
    }

    function probegVpered(formulaString, pos)
    {
        if (isNumber(formulaString[pos]))
        {
            while(isNumber(formulaString[pos]))
            {
                ++pos
            }
        }
        else if (formulaString[pos] === '(')
        {
            while(formulaString[pos] !== ')')
            {
                ++pos
            }
        }
        return pos
    }


    function scobkiFormula(formulaString)
    {
        ////console.log(formulaString)
        ////console.log("Start scobkiFormula----------------------")
        ////console.log("Start * / ----------------------")

        for(var i = 0; i < formulaString.length; ++i)
        {
            if (formulaString[i] === "*" || formulaString[i] === "/")
            {
                //console.log(formulaString)
                //console.log("formulaString.length = " + formulaString.length)
                //console.log("[" + i + "] = " + formulaString[i])

                //console.log("probegNazad")
                var pos = probegNazad(formulaString, i -1)
                formulaString = formulaString.substring(0, pos + 1) + '(' + formulaString.substring(pos+1, formulaString.length)
                ++i
                //console.log(formulaString)
                //console.log("formulaString.length = " + formulaString.length)
                //console.log("[" + i + "] = " + formulaString[i])

                // probeg vpered
                //console.log("probegVpered")
                pos = probegVpered(formulaString, i + 1)
                formulaString = formulaString.substring(0, pos) + ')' + formulaString.substring(pos, formulaString.length)
                ++i
                //console.log(formulaString)
                //console.log("formulaString.length = " + formulaString.length)
                //console.log("[" + i + "] = " + formulaString[i])
            }
        }

        //console.log(formulaString)
        //console.log("Start + -  ----------------------")
        // + -
        for(i = 0; i < formulaString.length; ++i)
        {
            if (formulaString[i] === "+" || formulaString[i] === "-")
            {
                //console.log(formulaString)
                //console.log("formulaString.length = " + formulaString.length)
                //console.log("[" + i + "] = " + formulaString[i])

                //console.log("probegNazad")
                pos = probegNazad(formulaString, i -1)
                //console.log("pos is = " + pos)


                formulaString = formulaString.substring(0, pos + 1) + '(' + formulaString.substring(pos+1, formulaString.length)
                ++i
                //console.log(formulaString)
                //console.log("formulaString.length = " + formulaString.length)
                //console.log("[" + i + "] = " + formulaString[i])

                // probeg vpered
                //console.log("probegVpered")
                pos = probegVpered(formulaString, i + 1)
                formulaString = formulaString.substring(0, pos) + ')' + formulaString.substring(pos, formulaString.length)
                ++i
                //console.log(formulaString)
                //console.log("formulaString.length = " + formulaString.length)
                //console.log("[" + i + "] = " + formulaString[i])

            }
        }

        //console.log(formulaString)

        //console.log("End scobkiFormula----------------------")

        return formulaString
    }






























    function calcRec (str, start_pos)
	{
        var deystvie = "+";
		var is_double = false

		var result_pos = 0
		var result_res = 0.0
        var loc_res = {result_pos, result_res}

        var delitel = 1
        var curr_num = 0.0;

        //var otstup = ""

        console.log("Start recursia----------------------")
        console.log("str is = " + str)
        console.log(str.substring(start_pos, str.length))

        while (true)
		{
            if (start_pos >= str.length )
			{
                return {result_pos, result_res}
			}
            console.log("")
            console.log("")
            console.log("after while result_res = "  +  result_res)
            console.log(str[start_pos])
            console.log(start_pos)
            console.log(str)

			var it_find = numberDetection(str[start_pos]);

			if (it_find !== -1) // 0-9 or .
			{
				if(it_find === 10)
				{
					isDouble = true;
					delitel = 10
				}
				else
				{
					if(isDouble)
					{
						curr_num += it_find / delitel
						delitel *=10
					}
					else
					{
						curr_num = curr_num*10 + it_find
					}
				}
			}
            else if (str[start_pos] === "+" || str[start_pos] === "-" || str[start_pos] === "*" || str[start_pos] === "/")
			{
                switch (deystvie)
                {
                   case "+": result_res += curr_num; break
                   case "-": result_res -= curr_num; break
                   case "*": result_res *= curr_num; break
                   case "/": result_res /= curr_num; break
                }
				curr_num = 0;
                deystvie = str[start_pos];
			}
			else if (str[start_pos] === "(")
			{
                //deystvie = "+";





                //console.log("str[start_pos] = " + str + "[" + start_pos + "]" )

                loc_res = calcRec(str, (start_pos+1));

                console.log("after rec loc_res.result_res = "  +  loc_res.result_res)
                console.log("before deystvie" + " result_res = "  +  result_res)

                switch (deystvie)
                {
                   case "+": result_res += loc_res.result_res; break
                   case "-": result_res -= loc_res.result_res; break
                   case "*": result_res *= loc_res.result_res; break
                   case "/": result_res /= loc_res.result_res; break
                }
                start_pos = loc_res.result_pos;
                console.log("after " + deystvie + " result_res = "  +  result_res)
                console.log("after " + deystvie + " start_pos = "   +  start_pos)
        //        return {result_pos, result_res}
            }
			else if (str[start_pos] === ")")
			{
                //console.log("TUTA")
                switch (deystvie)
                {
  //              case "+": result_res += loc_res.result_res + curr_num; break
    //            case "-": result_res -= loc_res.result_res + curr_num; break
      //          case "*": result_res *= loc_res.result_res + curr_num; break
        //        case "/": result_res /= loc_res.result_res + curr_num; break
                case "+": result_res += curr_num; break
                case "-": result_res -= curr_num; break
                case "*": result_res *= curr_num; break
                case "/": result_res /= curr_num; break
                }

                result_pos = start_pos ;
                console.log("TUTA deystvie = "  +  deystvie)
                console.log("TUTA curr_num = "  +  curr_num)
                console.log("TUTA str = "  +  str)
                console.log("TUTA sub_str = "  +  str.substring(start_pos, str.length))
                console.log("TUTA start_pos = "  +  start_pos)
                console.log("TUTA result_res = "  +  result_res)
                return {result_pos, result_res}
            }
			++start_pos;
		}
    }
}



/*	function calcRec (str, start_pos)
    {
        var deystvie = 1;
        var is_double = false

        var result_pos = 0
        var result_res = 0.0
        var delitel = 1

        var curr_num = 0.0;
        //console.log(start_pos + " in start calcRec = " + str )
        while (true)
        {
            if (start_pos >= str.length )
            {
                return {result_pos, result_res}
            }

            var it_find = numberDetection(str[start_pos]);

            if (it_find !== -1) // 0-9 or .
            {
                if(it_find === 10)
                {
                    isDouble = true;
                    delitel = 10
                }
                else
                {
                    if(isDouble)
                    {
                        curr_num += it_find / delitel
                        delitel *=10
                    }
                    else
                    {
                        curr_num = curr_num*10 + it_find
                    }
                }
            }
            else if (str[start_pos] === "+")
            {
                result_res += deystvie * curr_num;
                curr_num = 0;
//тута сделать умножение
                deystvie = 1;
            }

            else if (str[start_pos] === "-")
            {
                result_res += deystvie * curr_num;
                curr_num = 0;
                deystvie = -1;
            }

            else if (str[start_pos] === "(")
            {
                //console.log("str[start_pos] = " + str + "[" + start_pos + "]" )
                var loc_res = calcRec(str, (start_pos+1));
                result_res +=deystvie * loc_res.result_res;
                start_pos = loc_res.result_pos;
            }
            else if (str[start_pos] === ")")
            {
                result_res += deystvie *curr_num;
                result_pos = start_pos ;
                return {result_pos, result_res}
            }
            ++start_pos;
        }
    }*/
