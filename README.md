# Neo 
*Can AI be used to better understand the complex landscape of CVEs?*
... Maybe it could assist bug bounty hunters in choosing target software based on their strengths/interests? 
... Maybe it could yield predictive analytics that help IT teams understand the risk associated with particular products?


# Usage
To build your local dataset clone ![The CVEProject](https://github.com/CVEProject/cvelistV5/) within this repo.
To build the main table `cve_data.csv` run `python3 utils.py` 


# Vulnerability Description Classifier
One interesting thing I've found so far is that using the history of vulnerability details and some simple initial labelling 
with simple string matching, we can build a Random Tree Classifier that reads descriptions of vulnerabilities and places them 
into one of the 18 classes of CVEs I had created. 

To Train such a model run:
`python3 cnn.py train`
To evaluate after training:
`python3 cnn.py evaluate [Text Description of Vulnerability]`
An example: 
![ex](https://raw.githubusercontent.com/cas1m1r/Neo/refs/heads/main/hypothetical_cve_classified.png)
