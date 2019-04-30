import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="socanalystarsenal",
    version="1.0.0",
    author="Daniele Perera",
    author_email="daniele.perera@gmail.com",
    description="Quick threat intel tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/danieleperera/SocAnalystArsenal",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU GPLv3 License",
        "Operating System :: Windows 10",
    ],
)