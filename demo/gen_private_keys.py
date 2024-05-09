import sys
import Confidentiality.Asymetric as asym


def main():
    fName = sys.argv[1]
    with open(fName, "w") as f:
        f.write("test")


if __name__ == "__main__":
    main()
