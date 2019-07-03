# PyRP1210

## Quick Start

Use 32-bit Python 3 only.

Install with `pip install PyRP1210`

Run with `python demo_PyRP1210.py`  (which needs to be created still)

## Description

An RP1210 library for python


### Packaging

Open a command prompt (cmd) that has the python path ready to go. In the `PyRP1210` directory (or wherever you saved the file) we will perform the following actions.

  1. Check dependencies and create an up to date `requirements.txt` file by running 

```pipreqs /path/to/project```

 or 

 ```pipreqs --force ./``` if you are already in the  `TruckCRYPT` directory

If this doesn't work, try ```pip install pipreqs``` first.

  1. Remove the setup utilities, if they are in requirements.txt

  2. Build a wheel

 ```python setup.py bdist_wheel```

  3. Upload to PiPy

```twine upload dist/*```

If you get `HTTPError: 400 Client Error: File already exists. for url: https://upload.pypi.org/legacy/`, then make sure you update the version number in setup.py. You'll have to delete the old dist directory and try steps 2 and 3 again.
