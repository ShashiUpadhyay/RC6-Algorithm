all: compile
compile:
	javac RC6.java
	java RC6 input.txt output.txt
	java RC6 input_d.txt output_d.txt
