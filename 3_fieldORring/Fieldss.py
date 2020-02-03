#!/usr/bin/env/python3

def prime(number):
    factor = 2
    while factor <= int(number**0.5):
        if number%factor == 0:
            print("ring")
            return
        else:
            factor += 1
    print("field")
    return


if __name__ == "__main__":
    n = input("Enter an integer smaller than 50:")
    prime(int(n))
    # for i in range(2, 51):
    #     print(i)
    #     prime(i)
