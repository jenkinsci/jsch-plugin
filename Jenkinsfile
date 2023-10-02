// Build the plugin using https://github.com/jenkins-infra/pipeline-library
buildPlugin(useContainerAgent: true, configurations: [
        [platform: 'linux', jdk: '21'],
        [platform: 'linux', jdk: '11'],
        [platform: 'linux', jdk: '17', jenkins: '2.342'],
])
