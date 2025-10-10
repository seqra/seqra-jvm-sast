# Seqra JVM Sast

### Building Seqra using gradle

1. Install Seqra dependencies
   ```shell
   git submodule update --init --recursive
   ```

2. Create GitHub token to access dependencies published on GitHub. Follow
   an [official GitHub guide](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#creating-a-personal-access-token-classic).
3. Setup environment variables
   ```shell
   SEQRA_GITHUB_ACTOR=<your GitHub login>
   SEQRA_GITHUB_TOKEN=<GitHub token from step 2>
   ```
4. Run `gradle build`
