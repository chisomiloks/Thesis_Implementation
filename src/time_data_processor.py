def read_contents(file_name):
    # read content of file_name into a list of strings
    with open(file_name, 'r') as fopen:
        text = fopen.read()

    # print(text)
    # print("Type - ", type(text))

    list_of_text_strings = text.split('\n')
    # print(type(temp))
    # print(temp)
    # print(len(temp[:-1]))
    # return list minus the final element which is an empty string
    return list_of_text_strings[:-1]


def convert_list_strings_to_floats(list_of_strings):
    # list_of_floats = []
    # for item in list_of_strings:
    #     list_of_floats.append(float(item))
    # convert the list of strings to a list of floats
    list_of_floats = [float(item) for item in list_of_strings]
    return list_of_floats


if __name__ == "__main__":
    temp_list_strings = read_contents('My Scheme.txt')
    list_of_numbers = convert_list_strings_to_floats(temp_list_strings)

    print(temp_list_strings)
    print(list_of_numbers)