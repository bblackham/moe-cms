# Test cases for filter-cmt.c

Run:	./filter-cmt
In:	abc//comment
	de///fgh
	//full-line comment
	//another full-line comment
	lastline
Out:	abc
	de
	lastline
