#! /usr/bin/python

def less_than(arg1, arg2):
	if arg1 < arg2:
		return True
	return False

def greater_than(arg1, arg2):
	if arg1 > arg2:
		return True
	return False

def less_than_eq(arg1, arg2):
	if arg1 <= arg2:
		return True
	return False

def greater_than_eq(arg1, arg2):
	if arg1 >= arg2:
		return True
	return False

def equal_to(arg1, arg2):
	if arg1 == arg2:
		return True
	return False

def present_in(element, input_list):
	if element in input_list:
		return True
	return False

def get_extension(cert):

	extension_dict = {}
	
	for index in range(cert.get_extension_count()):	
		extension = cert.get_extension(index)
		ext_name = extension.get_short_name()
		extension_dict[ext_name] = extension

	return extension_dict
