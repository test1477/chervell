Got it! Here are the updated **UAT** and **PROD** deployment pipelines. These workflows will trigger **automatically on any commit to the `master` branch**, without requiring "Deploy" in the commit message.  

---

## **1. UAT Deployment Pipeline**
**Deploys all commits pushed to `master` to `/etc/ansible` on `ulsplk01-util0`.**

```yaml
name: Ansible UAT Deployment

on:
  push:
    branches:
      - master

jobs:
  Deploy-UAT:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Set Commit SHA
        id: sha
        run: echo "sha_short=$(git rev-parse --short HEAD)" >> $GITHUB_ENV

      - name: Deploy to UAT Server
        env:
          SSH_PRIVATE_KEY: ${{ secrets.UAT_SSH_KEY }}
        run: |
          echo "$SSH_PRIVATE_KEY" > private_key && chmod 600 private_key
          scp -o StrictHostKeyChecking=no -i private_key -r ./* ansible@ulsplk01-util0:/etc/ansible/
          ssh -o StrictHostKeyChecking=no -i private_key ansible@ulsplk01-util0 "cd /etc/ansible && ansible-playbook site.yml"

      - name: Clean Up
        run: rm -f private_key
```

---

## **2. PROD Deployment Pipeline**
**Deploys all commits pushed to `master` to `/etc/ansible` on `plsplk01-util0`.**

```yaml
name: Ansible PROD Deployment

on:
  push:
    branches:
      - master

jobs:
  Deploy-PROD:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Set Commit SHA
        id: sha
        run: echo "sha_short=$(git rev-parse --short HEAD)" >> $GITHUB_ENV

      - name: Deploy to PROD Server
        env:
          SSH_PRIVATE_KEY: ${{ secrets.PROD_SSH_KEY }}
        run: |
          echo "$SSH_PRIVATE_KEY" > private_key && chmod 600 private_key
          scp -o StrictHostKeyChecking=no -i private_key -r ./* ansible@plsplk01-util0:/etc/ansible/
          ssh -o StrictHostKeyChecking=no -i private_key ansible@plsplk01-util0 "cd /etc/ansible && ansible-playbook site.yml"

      - name: Clean Up
        run: rm -f private_key
```

---

## **🔹 Summary**
| Workflow | Trigger Condition | Target Server | Deployment Path |
|----------|-----------------|---------------|----------------|
| **UAT Deployment** | Any commit to `master` | `ulsplk01-util0` | `/etc/ansible` |
| **PROD Deployment** | Any commit to `master` | `plsplk01-util0` | `/etc/ansible` |

### **Key Features:**
✅ **Automatic deployment** on every commit to `master`.  
✅ **SSH authentication via GitHub Secrets** (`UAT_SSH_KEY` and `PROD_SSH_KEY`).  
✅ **Deploys all Ansible playbooks** and runs `site.yml` after deployment.  
✅ **Secure cleanup** of the private key after execution.  

Would you like any additional logging or error handling? 🚀
