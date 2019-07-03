import setuptools

with open("README.md","r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="PYRP1210",
    version="1.0.0",
    author="Jeremy Daily",
    author_email="zerojw@att.net",
    description="An RP1210 library for python",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Heavy-Vehicle-Networking-At-U-Tulsa/PyRP1210",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
