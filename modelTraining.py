from sklearn.preprocessing import LabelEncoder
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
from sklearn.metrics import precision_score, recall_score
from sklearn.model_selection import cross_val_score, cross_val_predict
import joblib


df = pd.read_csv("./NandakumarMenonAdvait_MT_S2.csv") 

#Encode IPs - trusted to 1, untrusted to 0
#note that 192.167.5.22 is the trusted IP in the dataset
df["Destination"] = (df["Destination"] == "192.167.5.22").astype(int)
df["Source"] = (df["Source"] == "192.167.5.22").astype(int)


#['ARP', 'ICMP', 'BROWSER', 'TLSv1.2', 'TCP', 'NBNS'] df["Protocol"].unique()

#Encode protocols
le = LabelEncoder()
df["Protocol"]=le.fit_transform(df['Protocol'])
#this makes: TCP=4, ICMP=2

df["Protocol"] = (df["Protocol"] == 2).astype(int)


#SPLIT DATASET ************************************
df=df.drop(columns=["Source Port","Destination Port"])

train_set_x, test_set_x = train_test_split(df, test_size=0.2, random_state=42)

train_set_y=train_set_x["bad_packet"]
train_set_x=train_set_x.drop(columns="bad_packet")

test_set_y=test_set_x["bad_packet"]
test_set_x=test_set_x.drop(columns="bad_packet")

#TRAIN MODEL **************************************
sgd_clf = SGDClassifier(random_state=42)
sgd_clf.fit(train_set_x,train_set_y)
y_pred=sgd_clf.predict(test_set_x) #use the model
test_set_x.sample(1)


#EVALUATE PERFORMACE ************************************

accuracy = accuracy_score(test_set_y, y_pred)
print(accuracy)

y_train_pred = cross_val_predict(sgd_clf, train_set_x, train_set_y, cv=5)

print(cross_val_score(sgd_clf, train_set_x, train_set_y, cv=5, scoring="accuracy")) 
print(precision_score(train_set_y, y_train_pred) )
print(recall_score(train_set_y, y_train_pred) )

confusion_matrix(train_set_y, y_train_pred)


#Finally, export model:

joblib.dump(sgd_clf, "ICMPflood_detector.pkl")
