from setuptools import setup

setup(
    name="test_setup",
    version="0.0.1",
    description="",
    packages=[
        "test_setup",
    ],
    python_requires=">=3.6",
    install_requires=["A>=1.0.0", "B==0.1.2"],
    test_suite="tests",
    tests_require=["C==2.3.1"],
)
