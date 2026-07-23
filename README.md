# ICMPmole
## Machine-learning based ICMP flood detection tool
Dataset used: https://www.kaggle.com/datasets/advaitnmenon/network-traffic-data-malicious-activity-detection?resource=download
## Model Training and reasoning
Upon inspecting the dataset, i noticed that ICMP is flagged as bad packet when coming from same source to same destination repeatedly.
And although flood can be done with TCP SYN as well, it seems that malicious TCP traffic was not used for this dataset making it limited only to detecting ICMP flood.

The original dataset included Source and Destination ports. However, since ICMP is not on the transport layer, there is no need for source and destination ports, only IP addresses, packet length, capture time, and protocol. 

When looking at the tail instances of the dataset, the packets at the end which have the highest timestamp values are flagged as bad packets, this could be an issue as the model could wrongfully associate higher time value with bad packets. 

As a result, the following preprocessing decisions were made:
1. Remove Source and Destination Ports columns.
2. Encode Protocols to the following values: 1 for ICMP and TCP, and 0 for all others. TCP was intentionally grouped with ICMP to allow for improvement in future work including TCP flood detection.
3. Encode IP addresses to 1 for internal and trusted IPs (only 192.167.5.22 in the case of the dataset), and 0 for all others.
   The encoding of IPs follows the access control concept of splitting the network to security zones (trusted, untrusted...etc) which reduces the complexity of the model.

The encoding being restricted to 1 and 0 is because encoding IPs or Protocols as numbers (1,2,3,4,5...) could lead to bias (e.g. higher source IP value = malicious, lower protocol value = malicious).

Then, Stochastic Gradient Descent (SGD) was used for the model because of its efficiency, ability to handle large datasets, and suitability for binary classification tasks.

## Performance Evaluation:
<b>With timestamps: </b>

Cross Validation Scores (5 folds): [0.99999807 1.         1.         1.         1.        ]

Accuracy:0.9999984592534158

Precision: 0.9999988428256347

Recall: 1.0

Confusion Matrix:

[[3622, 3],

 [0, 2592519]]



<br>
<b> Without timestamps: </b>

Cross Validation Scores  (5 folds): [0.99999807  1.         1.         1.         0.99999615]

Accuracy:0.9999984592534158

Precision:0.9999988428256347

Recall:1.0

Confusion Matrix:

[[3622, 3],

 [0, 2592519]]



*** The final model was trained with timestamps due to higher Cross Validation scores. ***
