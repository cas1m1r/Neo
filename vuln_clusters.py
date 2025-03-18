import pandas as pd
import matplotlib.pyplot as plt
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from vuln_explorer import *


def pre_process_impacts(cve_data):
    im_idx = []
    for rating in list(cve_data['Impact']):
        if rating == '?':
            im_idx.append('0')
        else:
            im_idx.append(float(rating))
    cve_data['Impact'] = np.array(im_idx)
    return cve_data


def pre_process_vectors(cve_data):
    vectors = unique(list(cve_data['AttackVector']))
    d = dict(zip(vectors, list(range(len(vectors)))))
    cve_data['AttackVector'] = [d[row] for row in cve_data['AttackVector']]
    return cve_data


def pre_process_severity(cve_data):
    severities = unique(list(cve_data['Severity']))
    d = dict(zip(severities, list(range(len(severities)))))
    cve_data['Severity'] = [d[row] for row in cve_data['Severity']]
    return cve_data


def pre_process_complexity(cve_data):
    levels = unique(list(cve_data['complexity']))
    d = dict(zip(levels, list(range(len(levels)))))
    cve_data['complexity'] = [d[row] for row in cve_data['complexity']]
    return cve_data


def pre_process_privilege(cve_data):
    levels = unique(list(cve_data['requiredPrivilege']))
    d = dict(zip(levels, list(range(len(levels)))))
    cve_data['requiredPrivilege'] = [d[row] for row in cve_data['requiredPrivilege']]
    return cve_data


def pre_process_cveid(cve_data):
    cve_idx = [int(s.replace('CVE-','').replace('-','')) for s in list(cve_data['CVE'])]
    # replace column in CVE_data with all ints of cve_idx
    cve_data['CVE'] = cve_idx
    return cve_data


def pre_process_dates(cve_data):
    dates = list(cve_data['date'])

    date_idx = []
    for d in dates:
        try:
            d = datetime.datetime.timestamp(datetime.datetime.fromisoformat(d))
        except ValueError:
            d = 0
            pass
        date_idx.append(d)
    cve_data['date'] = date_idx
    return cve_data


def pre_process_vendors(cve_data):
    vendors = unique(cve_data['vendor'])
    d = dict(zip(vendors, list(range(len(vendors)))))
    # give each vendor a number
    vendors = [d[row] for row in cve_data['vendor']]
    # convert entire table using vendor_idx
    cve_data['vendor'] = vendors
    return cve_data, vendors


def pre_process_product(cve_data):
    products = unique(cve_data['product'])
    d = dict(zip(products, list(range(len(products)))))
    cve_data['product'] = [d[row] for row in cve_data['product']]
    return cve_data, d

def pre_process_reporter(cve_data):
    reporters = cve_data['finder']
    d = dict(zip(reporters, list(range(len(reporters)))))
    cve_data['finder'] = [d[row] for row in cve_data['finder']]
    return cve_data, d


if __name__ == '__main__':
    df = pd.read_csv('cve_data.csv')
    df = df.dropna()  # Or use other imputation techniques

    features = ['CVE','date', 'vendor', 'product', 'finder', 'vuln_class',
                'Impact','AttackVector','Severity','complexity', 'requiredPrivilege']
    # TODO: reduce vendors/products/finders by a unique ID
    df = pre_process_cveid(df)
    df = pre_process_dates(df)
    df = pre_process_impacts(df)
    df = pre_process_vectors(df)
    df = pre_process_severity(df)
    df = pre_process_complexity(df)
    df = pre_process_privilege(df)

    df, vendorMapping = pre_process_vendors(df)
    df, productMapping = pre_process_product(df)
    df, reporterMapping = pre_process_reporter(df)

    print(f'[+] Saving PreProcessed Table to PreProcessedCVEData.csv')
    df[features].to_csv('PreProcessedCVEData.csv')

    features = ['vendor', 'product', 'vuln_class', 'AttackVector', 'Severity', 'complexity', 'requiredPrivilege']
    X = df[features]
    Y = df['Impact']
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    inertia = []
    for k in range(1, 42):
        kmeans = KMeans(n_clusters=k, random_state=42, n_init='auto')
        kmeans.fit(X_scaled)
        inertia.append(kmeans.inertia_)

    plt.plot(range(1, 42), inertia, marker='o')
    plt.xlabel('Number of Clusters (K)')
    plt.ylabel('Inertia')
    plt.title('Elbow Method for Optimal K')
    plt.show()

    import numpy as np
    # from sklearn.decomposition import PCA
    # #
    # #
    # pca = PCA(n_components=5)
    # pca.fit(X)
    # Scaled_data = pca.transform(df[features])
    # #
    # # Set the n_components=3
    # principal = PCA(n_components=5)
    # principal.fit(Scaled_data)
    # x = principal.transform(Scaled_data)
    # import relevant libraries for 3d graph
    from mpl_toolkits.mplot3d import Axes3D

    # fig = plt.figure(figsize=(10, 10))

    # choose projection 3d for creating a 3d graph
    # axis = fig.add_subplot(111, projection='3d')

    # x[:,0]is pc1,x[:,1] is pc2 while x[:,2] is pc3
    # axis.scatter(x[:, 1], x[:, 2], x[:, 3], c=df['vuln_class'], cmap='plasma')
    # axis.set_xlabel("PC1", fontsize=10)
    # axis.set_ylabel("PC2", fontsize=10)
    # axis.set_zlabel("PC3", fontsize=10)
    # plt.show()

    k = 30  # Replace with your chosen optimal K
    kmeans = KMeans(n_clusters=k, random_state=42, n_init='auto')
    df['cluster'] = kmeans.fit_predict(X_scaled)
    N = list(range(X_scaled.shape[1]))
    # from itertools import combinations
    # for combo in combinations(N,2):
    #     plt.scatter(X_scaled[:, combo[0]], X_scaled[:, combo[1]], c=df['cluster'], label='Data Points')
    #     plt.title('K-means Clustering')
    #     plt.xlabel(f'Feature {features[combo[0]]}')
    #     plt.ylabel(f'Feature {features[combo[1]]}')
    #     plt.legend()
    #     plt.show()
    #     plt.savefig(f'kmean_feature{combo[0]}_feauture_{combo[1]}.png')
    from svm import *
    input_dim = len(features)
    learning_rate = 0.001
    model = LinearSVM(input_dim)
    criterion = nn.HingeEmbeddingLoss()
    optimizer = optim.Adam(model.parameters(), lr=learning_rate)

    epochs = 100
    for epoch in range(epochs):
        optimizer.zero_grad()
        outputs = model(X).squeeze()
        loss = criterion(outputs, Y)
        loss.backward()
        optimizer.step()
        print(f'Epoch [{epoch+1}/{epochs}], Loss: {loss.item():.4f}')