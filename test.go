package main

import (
	"fmt"
	"time"
	"strconv"
)

func main() {
	fmt.Print(time.Now().Unix())
}
func progress(module string,length int64,offset int64)  {
	str := "[" + bar(int(length/offset), 100) + "] " + strconv.FormatInt(length/offset,10) + "%"
	fmt.Printf("\r%s", str)
}
func bar(count int, size int) string {
	str := ""
	for i := 0; i < size; i++ {
		if i < count {
			str += "="
		} else {
			str += " "
		}
	}
	return str
}
