package lsss

import (
	"github.com/golang-collections/collections/stack"
)

//https://raj457036.github.io/Simple-Tools/prefixAndPostfixConvertor.html
func notOperator(s rune) bool {
	return s >= 'a' && s <= 'z' || s >= 'A' && s <= 'Z' || s >= '0' && s <= '9'
}

func isOperator(s rune) bool {
	return !(s >= 'a' && s <= 'z' || s >= 'A' && s <= 'Z' || s >= '0' && s <= '9')
}

func getPriority(s rune) int {
	if s == '-' || s == '+' {
		return 1
	} else if s == '*' || s == '/' {
		return 2
	} else if s == '^' {
		return 3
	}

	return 0
}

func infixToPostfix(infix string) string {
	infix = "(" + infix + ")"

	charStack := stack.New()
	var output string

	// (l-k/a)*(c/b-a)
	for _, value := range infix {

		if notOperator(value) {
			output += string(value)
		} else if value == '(' {
			charStack.Push("(")
		} else if value == ')' {
			for {
				if charStack.Peek().(string) != "(" {
					output += charStack.Peek().(string)
					charStack.Pop()
				} else {
					break
				}
			}

			charStack.Pop()
		} else {
			if charStack.Peek() != nil {
				if isOperator(rune(charStack.Peek().(string)[0])) {
					for {
						if getPriority(value) <= getPriority(rune(charStack.Peek().(string)[0])) {
							output += charStack.Peek().(string)
							charStack.Pop()
						} else {
							break
						}
					}

					// Push current Operator on stack
					charStack.Push(string(value))
				}
			}
		}
	}

	return output
}

func InfixToPrefix(infix string) string {
	infix = reverseString(infix)

	binfix := []byte(infix)
	// Replace ( with ) and vice versa
	for i := 0; i < len(infix); i++ {
		if binfix[i] == '(' {
			binfix[i] = ')'
		} else if binfix[i] == ')' {
			binfix[i] = '('
		}
	}
	infix = string(binfix)

	var prefix string

	prefix = infixToPostfix(infix)
	// Reverse postfix
	prefix = reverseString(prefix)
	prefix = lsssFormat(prefix)

	return prefix
}

func reverseString(s string) string {
	runes := []rune(s)
	for from, to := 0, len(runes)-1; from < to; from, to = from+1, to-1 {
		runes[from], runes[to] = runes[to], runes[from]
	}
	return string(runes)

}

func lsssFormat(prefix string) (output string) {
	var sumNode, sumOper int
	var count int = 1
	var switchOper, switchBiffle bool
	var temp string
	for _, value := range prefix {
		switch string(value) {
		case "*":
			sumNode = 0
			sumOper++
		case "+":
			sumNode = 0
			sumOper++
		default:
			switchOper = true
			sumOper = 0
			sumNode++
		}

		if sumOper == 2 && switchOper {
			len := len(temp) - 1
			var baffle string
			if switchBiffle {
				count++
				for i := 0; i < count; i++ {
					baffle += "|"
				}
			} else {
				baffle = "|"
			}

			output = output + temp[:len] + baffle + temp[len:]
			temp = ""
			temp += string(value)

			switchBiffle = !switchBiffle
		} else if sumNode == 3 {
			var baffle string
			baffle = "!"
			temp += string(value)
			output = output + temp + baffle
			temp = ""
		} else {
			temp += string(value)
		}
	}

	output += temp

	length := len(output)
	if output[length-1:] == "!" {
		output = output[:length-2] + "|" + output[length-2:length-1]
	}

	return
}
