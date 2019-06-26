package file

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// A ListDirectory represents a Struct.
type ListDirectory struct {
	Directory *string
	Date      time.Time
	Size      *int64
}

// A TimeSlice represents a List of ListDirectory.
type TimeSlice []ListDirectory

// GetAllFileName returns the string of a filename and ext.
func (ld ListDirectory) GetAllFileName() string {
	return filepath.Base(*ld.Directory)
}

// GetFileName returns the string of a filename.
func (ld ListDirectory) GetFileName() string {
	allFileName := filepath.Base(*ld.Directory)
	getExt := filepath.Ext(*ld.Directory)

	return allFileName[:len(allFileName)-len(getExt)]
}

// GetExt returns the string of a ext.
func (ld ListDirectory) GetExt() string {
	getExt := filepath.Ext(*ld.Directory)

	return getExt[1:]
}

func (p TimeSlice) Len() int {
	return len(p)
}

func (p TimeSlice) Less(i, j int) bool {
	return p[i].Date.Before(p[j].Date)
}

func (p TimeSlice) Swap(i, j int) {
	p[i], p[j] = p[j], p[i]
}

// GetAllFile returns the List of a Sort Directory.
func GetAllFile(path, ext string) TimeSlice {
	var listMap = make(map[string]ListDirectory)

	filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() {
			if strings.ToLower(filepath.Ext(path)) == "."+strings.ToLower(ext) {
				dirInfo, err := os.Stat(path)
				if err != nil {
					return err
				}
				fileSize := dirInfo.Size()
				listMap[filepath.Base(path)] = ListDirectory{Directory: &path, Date: dirInfo.ModTime(), Size: &fileSize}
			}
		}
		return nil
	})

	dateSortedReviews := make(TimeSlice, 0, len(listMap))
	for _, d := range listMap {
		dateSortedReviews = append(dateSortedReviews, d)
	}

	sort.Sort(dateSortedReviews)

	return dateSortedReviews
}
