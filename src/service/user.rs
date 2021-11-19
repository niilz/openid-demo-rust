use std::collections::HashMap;
use std::fmt::Debug;
use std::marker::PhantomData;

#[derive(Default)]
pub struct InMemoryUserRepository {
    index: u32,
    users: HashMap<u32, User<Conserved>>,
}

impl InMemoryUserRepository {
    pub fn save(&mut self, user: User<Fresh>) -> u32 {
        self.index += 1;
        let conserve_user = user.set_id(self.index);
        let id = conserve_user.get_id();
        self.users.insert(self.index, conserve_user);
        id
    }

    pub fn get_idx(&self) -> u32 {
        self.index
    }

    pub fn get_user_by_id(&self, id: u32) -> Result<User<Conserved>, &'static str> {
        match self.users.get(&id).to_owned() {
            Some(user) => Ok((*user).clone()),
            None => Err("User did not exist"),
        }
    }
    pub fn get_user_by_name(&self, name: impl AsRef<str>) -> Option<User<Conserved>> {
        match self
            .users
            .iter()
            .find(|(_id, user)| user.get_name() == name.as_ref())
        {
            Some((_id, user)) => Some((*user).clone()),
            None => None,
        }
    }
}

pub trait Persistence {}

#[derive(Debug, PartialEq, Eq)]
pub struct Fresh;
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct Conserved;

impl Persistence for Fresh {}
impl Persistence for Conserved {}

#[derive(PartialEq, Eq, Debug, Hash, Clone)]
pub struct User<P: Persistence> {
    id: Option<u32>,
    name: String,
    _state: PhantomData<P>,
}

impl User<Fresh> {
    pub fn new(name: String) -> Self {
        User {
            id: None,
            name,
            _state: PhantomData::default(),
        }
    }

    fn set_id(self, id: u32) -> User<Conserved> {
        User {
            name: self.name,
            id: Some(id),
            _state: PhantomData::default(),
        }
    }
}

impl User<Conserved> {
    pub fn get_name(&self) -> &'_ str {
        &self.name
    }
    pub fn get_id(&self) -> u32 {
        // A Conserved-User always has an ID
        assert!(self.id.is_some());
        self.id.unwrap()
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use crate::service::user::Conserved;

    use super::InMemoryUserRepository;
    use super::User;

    #[test]
    fn can_add_user_to_repo() {
        let user = User::new("Marty".to_string());
        let mut repo = InMemoryUserRepository::default();

        assert_eq!(0, repo.users.len());
        assert_eq!(0, repo.get_idx());

        repo.save(user);
        assert_eq!(1, repo.users.len());
        assert_eq!(1, repo.get_idx());
    }

    #[test]
    fn can_get_user_name_after_it_has_been_persisted() {
        let expected_name = "Marty".to_string();
        let new_user = User::new(expected_name.clone());
        // Would not work because 'get_name()' only exitst on User<Conserved>
        // not ont User<Fresh>
        // new_user.get_name();
        let conserved_user = new_user.set_id(42);
        let name = conserved_user.get_name();
        assert_eq!(expected_name, name);
    }

    #[test]
    fn non_existing_user_returns_none() {
        // Empty Repo
        let repo = InMemoryUserRepository::default();
        assert_eq!(None, repo.get_user_by_name("Unknown"));
    }

    #[test]
    fn inserted_user_can_be_found() {
        let mut repo = InMemoryUserRepository::default();
        let new_user = User::new("Marty".to_string());
        let new_id = repo.save(new_user);
        assert_eq!(new_id, 1);

        let expected_user = User {
            id: Some(1),
            name: "Marty".to_string(),
            _state: PhantomData::default(),
        };

        let persisted_user = repo.get_user_by_name("Marty");
        assert_eq!(persisted_user, Some(expected_user));
    }
}
