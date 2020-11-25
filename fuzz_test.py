__author__ = 'L3odr0id'
"""
Fuzz testing
"""
import time
from fuzzingbook.Fuzzer import RandomFuzzer
from aes import AES


def test_system(key, data):
    """
    Encrypt and decrypt @key and @data
    """
    a = AES(key)

    plaintext = data
    encrypted = a.encrypt(plaintext)
    decrypted = a.decrypt(encrypted)

    # check if data is encrypted
    assert encrypted != decrypted, 'Data is not encrypted!'

    return decrypted


def fuzz_testing(num_of_tests=10):
    """
    Do tests
    """
    ok = True
    start = time.clock()
    errors = []

    # generate integers. Max possible length is 38
    r = RandomFuzzer(min_length=1, char_start=48, char_range=9, max_length=38)

    dot = num_of_tests // 10    # decoration stuff

    for i in range(0, num_of_tests):
        if i % dot == 0:
            print('.', end='')
        # generate test case
        key = int(r.fuzz())
        data = int(r.fuzz())

        # analyze output
        try:
            result = test_system(key, data)
            if data != result:
                errors.append('TEST ' + str(i) + ' FAILED\nKey = "' + str(key) + '"\nData = "' + str(data) + '"')
                errors.append('Result = "'+str(result)+'"')
                errors.append('Reason: Error in encryption - decryption process\n')
                ok = False
        except AssertionError:
            errors.append('TEST '+str(i)+' FAILED\nKey = "'+str(key)+'"\nData = "'+str(data)+'"')
            errors.append('Reason: Data was not encrypted\n')
            ok = False

    # print testing results
    elapsed = time.clock()
    elapsed = elapsed - start
    print()
    for i in errors:
        print(i)
    print('Ran ' + str(num_of_tests) + ' tests in '+str(round(elapsed, 3))+'s')
    print()
    if ok:
        print('OK')
    else:
        print('FAILED')


if __name__ == "__main__":
    print('Fuzz test started.')
    fuzz_testing(1337)
