import log
import sys
import tests.tests as tests


def run():
    log.configure()
    print("test key saving:", tests.test_key_saving(), "\n\n")
    print("test asym encryption:", tests.test_asym_encryption(), "\n\n")
    print("test sym encryption:", tests.test_sym_encryption(), "\n\n")
    print("test pgp encryption:", tests.test_pgp_encryption(), "\n\n")


if __name__ == "__main__":
    run()
