package lsss

import (
	"fmt"

	"gonum.org/v1/gonum/mat"
)

// SolutionEquation is good
func SolutionEquation(attrField map[string][]int) (c2f []float64) {
	var rowLen int    // 行
	var columnLen int // 列

	columnLen = len(attrField)

	v := []float64{}

	for _, array := range attrField {
		rowLen = len(array)
		for _, value := range array {
			v = append(v, float64(value))
		}
	}

	for i := 0; i < rowLen-columnLen; i++ {
		for j := 0; j < rowLen; j++ {
			v = append(v, float64(0))
		}
	}

	// fmt.Println(columnLen, rowLen)
	A := mat.NewDense(rowLen, rowLen, v)
	// fmt.Println("MatrixA:")
	// matPrint(A)

	v = make([]float64, rowLen)
	v[0] = 1
	B := mat.NewDense(rowLen, 1, v)
	// fmt.Println("MatrixB:")
	// matPrint(B)

	A.Inverse(A.T())
	// fmt.Println("MatrixA^T_inv:")
	// matPrint(A)

	C := mat.NewDense(rowLen, 1, nil)
	C.Product(A, B)
	// fmt.Println("Ans:")
	// matPrint(C)

	c2f = make([]float64, rowLen)
	mat.Col(c2f, 0, C)

	return
}

func matPrint(X mat.Matrix) {
	fa := mat.Formatted(X, mat.Prefix(""), mat.Squeeze())
	fmt.Printf("%v\n\n", fa)
}
