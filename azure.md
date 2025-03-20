name: CI

on:
  workflow_call:
    inputs:
      environment:
        description: "Environment to deploy (e.g., dev, qa)"
        required: true
        type: string
      branch:
        description: "Branch with Terraform to run"
        required: true
        type: string
      terraform_version:
        description: "Terraform version to install (e.g., 0.13.5)"
        required: true
        type: string
      working_directory:
        description: "Directory to run Terraform commands"
        required: true
        type: string

jobs:
  terraform:
    name: Terraform Workflow
    runs-on: ubuntu-latest
    environment: ${{ inputs.environment }}
    env:
      ARM_CLIENT_ID: ${{ secrets.AZURE_CLIENT_ID }}
      ARM_CLIENT_SECRET: ${{ secrets.AZURE_CLIENT_SECRET }}
      ARM_SUBSCRIPTION_ID: ${{ secrets.SUBSCRIPTION_ID }}
      ARM_TENANT_ID: ${{ secrets.AZURE_TENANT_ID }}
      AZURE_CLIENT_ID: ${{ secrets.AZURE_CLIENT_ID }}
      AZURE_CLIENT_SECRET: ${{ secrets.AZURE_CLIENT_SECRET }}
      AZURE_SUBSCRIPTION_ID: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
      AZURE_TENANT_ID: ${{ secrets.AZURE_TENANT_ID }}
      CWD: ${{ inputs.working_directory }}

    steps:
      # Install Azure CLI and PowerShell from JFrog
      - name: Install Azure CLI and PowerShell from JFrog
        env:
          JFROG_API_TOKEN: ${{ secrets.JFROG_API_TOKEN }}
        run: |
          # Install prerequisites
          sudo apt-get update
          sudo apt-get install -y apt-transport-https ca-certificates curl gnupg lsb-release

          # Add JFrog remote repository for Azure CLI
          echo "deb [signed-by=/usr/share/keyrings/jfrog-azure-cli-archive-keyring.gpg] https://your-jfrog-instance.jfrog.io/artifactory/azure-cli-repo/ $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/azure-cli.list
          curl -sSfL https://your-jfrog-instance.jfrog.io/artifactory/azure-cli-repo/azure-cli-archive-keyring.gpg | sudo tee /usr/share/keyrings/jfrog-azure-cli-archive-keyring.gpg > /dev/null

          # Add JFrog remote repository for PowerShell
          echo "deb [signed-by=/usr/share/keyrings/jfrog-powershell-archive-keyring.gpg] https://your-jfrog-instance.jfrog.io/artifactory/powershell-repo/ $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/powershell.list
          curl -sSfL https://your-jfrog-instance.jfrog.io/artifactory/powershell-repo/microsoft.gpg | sudo tee /usr/share/keyrings/jfrog-powershell-archive-keyring.gpg > /dev/null

          # Update package index and install Azure CLI and PowerShell
          sudo apt-get update
          sudo apt-get install -y azure-cli powershell

      # Configure Git
      - name: Configure Git
        run: |
          git config --global credential.helper store
          echo "https://${{ secrets.GHA_RUNNERS_TOKEN }}:@github.com" > ~/.git-credentials

      # Checkout source code
      - name: Checkout Source Code
        uses: actions/checkout@v3
        with:
          ref: ${{ inputs.branch }}

      # Configure Terraform API Token
      - name: Configure Terraform API Token
        env:
          ARTIFACTORY_TOKEN: ${{ secrets.ARTIFACTORY_TOKEN }}
        run: |
          mkdir -p ~/.terraform.d
          cat <<EOF > ~/.terraform.d/credentials.tfrc.json
          {
            "credentials": {
              "frigate.jfrog.io": {
                "token": "${ARTIFACTORY_TOKEN}"
              }
            }
          }
          EOF

      # Configure Terraform RC File
      - name: Configure Terraform RC File
        run: |
          mkdir -p ~/.terraform.d
          cat <<EOF > ~/.terraformrc
          provider_installation {
              direct {
                  exclude = ["registry.terraform.io/*/*"]
              }
              network_mirror {
                  url = "https://frigate.jfrog.io/artifactory/api/terraform/tf-providers-ppa-azure/providers/"
              }
          }
          EOF

      # Set up Terraform
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v1
        with:
          terraform_version: ${{ inputs.terraform_version }}
          terraform_wrapper: false

      # Show Terraform version
      - name: Echo Terraform Version
        run: terraform version

      # Initialize Terraform
      - name: Terraform Init
        id: init
        run: terraform init -backend-config="environments/${{ inputs.environment }}/backend.tfvars"

      # Validate Terraform configuration
      - name: Terraform Validate
        id: validate
        run: terraform validate

      # Plan Terraform deployment
      - name: Terraform Plan
        id: plan
        run: terraform plan -var-file="environments/${{ inputs.environment }}/main.tfvars"

      # Apply Terraform deployment
      - name: Terraform Apply
        working-directory: ${{ inputs.working_directory }}
        run: terraform apply -auto-approve -var-file="environments/${{ inputs.environment }}/main.tfvars"
