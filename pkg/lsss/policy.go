package lsss

type AccessPolicy struct {
	class int
	value []int
}

type stackTree struct {
	leftValue  []int
	rightValue []int
}

// AccessTree hi.
func AccessTree(prefix string) (attrNode map[string][]int) {
	var class, length int = 0, 1
	var Expression string
	var switchNode bool // false: left , true: right

	attrNode = make(map[string][]int)
	nd := make(map[int][]int)
	st := make(map[int]stackTree)

	for id, value := range prefix {
		Expression = string(value)

		if id == 0 {
			switch Expression {
			case "*":
				class++
				length++

				nd[id] = []int{1}

				rightValue := genRightNode(nd[id], length)

				st[class] = stackTree{leftValue: []int{0, -1}, rightValue: rightValue}
			case "+":
				class++

				nd[id] = []int{1}

				st[class] = stackTree{leftValue: []int{1}, rightValue: []int{1}}
			}
		} else {
			switch Expression {
			case "*":
				length++

				if switchNode {
					nd[id] = st[class].rightValue
					switchNode = !switchNode
				} else {
					nd[id] = st[class].leftValue
				}

				class++

				leftValue := genLeftNode(length)

				rightValue := genRightNode(nd[id], length)

				st[class] = stackTree{leftValue: leftValue, rightValue: rightValue}
			case "+":
				if switchNode {
					nd[id] = st[class].rightValue
					switchNode = !switchNode
				} else {
					nd[id] = st[class].leftValue
				}

				class++

				st[class] = stackTree{leftValue: nd[id], rightValue: nd[id]}
			case "|":
				class--
				if len(st[class].leftValue) == 0 {
					class++
				}
			case "!":
				class++
			default:
				if switchNode {
					attrNode[Expression] = st[class].rightValue
					class--
				} else {
					attrNode[Expression] = st[class].leftValue
					// switch to right
					switchNode = !switchNode
				}

			}
		}
	}

	for id, value := range attrNode {
		attrNode[id] = zeroFill(value, length)
	}

	return
}

func genLeftNode(length int) (res []int) {
	for i := 0; i < length-1; i++ {
		res = append(res, 0)
	}
	res = append(res, -1)

	return
}

func genRightNode(node []int, length int) (res []int) {
	res = []int{}
	res = append(res, node...)

	for i := len(node); i < length-1; i++ {
		res = append(res, 0)
	}

	res = append(res, 1)

	return
}

func zeroFill(attrNode []int, length int) []int {
	count := length - len(attrNode)
	if len(attrNode) < length {
		for i := 1; i <= count; i++ {
			attrNode = append(attrNode, 0)
		}
	}

	return attrNode
}
