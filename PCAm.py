import  pandas as  pd
import  numpy  as  np
import  matplotlib.pyplot as plt
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler
from numpy import array
from numpy import mean
from numpy import cov
from numpy.linalg import eig
from mpl_toolkits.mplot3d import Axes3D

url = open("dataPCAm.csv","r")

df = pd.read_csv(url,names=['characters','suspWord','sql','kolmogorov','url','class'])
df.tail()
X = df.iloc[:,0:5].values
y = df.iloc[:,5].values
#r = np.isnan(X)

X_std = StandardScaler().fit_transform(X)
fff = X_std[0]
print('NumPy covariance matrix: \n%s' %np.cov(X_std.T))
cov_mat = np.cov(X_std.T)
eig_vals, eig_vecs = np.linalg.eig(cov_mat)
print('Eigenvectors \n%s' %eig_vecs)
print('\nEigenvalues \n%s' %eig_vals)
eig_pairs = [(np.abs(eig_vals[i]), eig_vecs[:,i]) for i in range(len(eig_vals))]

print('\n')
# Ordenamos estas parejas den orden descendiente con la funcion sort
eig_pairs.sort(key=lambda x: x[0], reverse=True)
#pares autovalor autovector
#print("pairs")
#print(eig_pairs)
pares = []
index = []
for i in range(len(eig_vals)):
    pares.append((eig_vals[i],eig_vecs[:,i]))
    index.append(eig_vals[i])
index.sort()
print("**************************************************")
for i in pares:
    #print(i)
    pass

#eigenpares visualizacion
"""print("EIGEN PARES")
for i in eig_pairs:
    print(i)"""

# Visualizamos la lista de autovalores en orden descendente
tot = sum(eig_vals)
var_exp = [(i / tot)*100 for i in sorted(eig_vals, reverse=True)]
cum_var_exp = np.cumsum(var_exp)

with plt.style.context('seaborn-whitegrid'):
    plt.figure(figsize=(5, 5))

    plt.bar(range(5), var_exp, alpha=0.5, align='center',
            label='Varianza individual explicada', color='r')
    plt.step(range(5), cum_var_exp, where='mid', linestyle='--', label='Varianza explicada acumulada')
    plt.ylabel('Ratio de Varianza Explicada')
    plt.xlabel('Componentes Principales')
    plt.legend(loc='best')
    plt.title('VARIANZA EXPLICADA')
    plt.tight_layout()
    
matrix_w = np.hstack((eig_pairs[0][1].reshape(5,1),
                      eig_pairs[1][1].reshape(5,1)))#taking two PCAs

matrix_w3D = np.hstack( (eig_pairs[0][1].reshape(5,1),
                        eig_pairs[1][1].reshape(5,1),
                        eig_pairs[2][1].reshape(5,1)))

print("PCAs")
print(eig_pairs[0][1])
print(eig_pairs[1][1])
print(eig_pairs[2][1])
print("*************************************************")
print("MATRIZ W3D")
print(matrix_w3D)

Y = X_std.dot(matrix_w)
Y3D = X_std.dot(matrix_w3D)
print("********************************************")
print("MATRIZ Y")
print(Y)
print("MATRIZ Y 3D")
print(Y3D)
index, index3D = 0,0
finalPoints = []
finalPoints3D = []
for point in Y:
    finalPoints.append([point[0],point[1],y[index]])
    index += 1
for point in Y3D:
    finalPoints3D.append([point[0],point[1],point[2],y[index3D]])
    index3D += 1
    
anomalousY = []
anomalousX = []
anomalousZ = []
normalY = []
normalX = []
normalZ = []

for point in finalPoints:
    if point[len(point)-1] == "anomalous":
        anomalousX.append(point[0])
        anomalousY.append(point[1])
    elif point[len(point)-1] == "normal":
        normalX.append(point[0])
        normalY.append(point[1])

for point in finalPoints3D:
    if point[len(point)-1] == "anomalous":
        anomalousZ.append(point[2])
    elif point[len(point)-1] == "normal":
        normalZ.append(point[2])

with plt.style.context('seaborn-whitegrid'):
    fig = plt.figure()
    ax = fig.add_subplot(111, projection='3d')
    ax.scatter(normalX,normalY,normalZ, c='b',marker ='o')
    ax.scatter(anomalousX,anomalousY,anomalousZ, c='r',marker ='o')
    ax.set_xlabel('X')
    ax.set_ylabel('Y')
    ax.set_zlabel('Z')
    plt.title('3 PCAs')

with plt.style.context('seaborn-whitegrid'):
    plt.figure(figsize=(5, 5))
    plt.plot(anomalousX,anomalousY,'ro',normalX,normalY,'bo')
    plt.ylabel('Y')
    plt.xlabel('X')
    plt.legend(loc='best')
    plt.tight_layout()
    plt.title('2 PCAs')
    plt.grid()

plt.show()


