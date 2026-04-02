use crate::error::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceConnectionName {
    pub project: String,
    pub region: String,
    pub instance: String,
}

impl InstanceConnectionName {
    pub fn parse(name: &str) -> Result<Self, Error> {
        let parts: Vec<&str> = name.split(':').collect();
        if parts.len() != 3 {
            return Err(Error::InvalidInstanceName(format!(
                "expected format 'project:region:instance', got '{name}'"
            )));
        }

        let project = parts[0].trim();
        let region = parts[1].trim();
        let instance = parts[2].trim();

        if project.is_empty() || region.is_empty() || instance.is_empty() {
            return Err(Error::InvalidInstanceName(format!(
                "project, region, and instance must not be empty, got '{name}'"
            )));
        }

        Ok(Self {
            project: project.to_string(),
            region: region.to_string(),
            instance: instance.to_string(),
        })
    }

    pub fn api_path(&self) -> String {
        format!("projects/{}/instances/{}", self.project, self.instance)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_instance_name() {
        let name = InstanceConnectionName::parse("my-project:us-central1:my-instance").unwrap();
        assert_eq!(name.project, "my-project");
        assert_eq!(name.region, "us-central1");
        assert_eq!(name.instance, "my-instance");
    }

    #[test]
    fn test_parse_invalid_format() {
        assert!(InstanceConnectionName::parse("invalid").is_err());
        assert!(InstanceConnectionName::parse("project:region").is_err());
        assert!(InstanceConnectionName::parse("a:b:c:d").is_err());
    }

    #[test]
    fn test_parse_empty_parts() {
        assert!(InstanceConnectionName::parse(":region:instance").is_err());
        assert!(InstanceConnectionName::parse("project::instance").is_err());
        assert!(InstanceConnectionName::parse("project:region:").is_err());
    }

    #[test]
    fn test_api_path() {
        let name = InstanceConnectionName::parse("my-project:us-central1:my-instance").unwrap();
        assert_eq!(name.api_path(), "projects/my-project/instances/my-instance");
    }
}
