
# JSch Jenkins Plugin
[![Jenkins Plugin](https://img.shields.io/jenkins/plugin/v/jsch.svg?color=blue)](https://plugins.jenkins.io/jsch)
[![Jenkins Plugin Installs](https://img.shields.io/jenkins/plugin/i/jsch.svg?color=blue)](https://plugins.jenkins.io/jsch)


This plugin provides a shared dependency on the `com.jcraft:jsch` JAR -
using this plugin will eliminate the classloader problems caused by
having multiple copies of jsch loaded.**This plugin is not meant to be
used by end users by itself.**

It's supposed to be included through the dependencies of other plugins,
which want to use JSch library with support for SSH Credentials plugin.

## Version History
Please refer to [the changelog](CHANGELOG.md).
