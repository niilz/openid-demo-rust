use std::collections::HashMap;
use std::marker::PhantomData;

pub struct InMemoryUserRepository {
    index: u32,
    users: HashMap<u32, User<Conserved>>,
}

impl Default for InMemoryUserRepository {
    fn default() -> Self {
        InMemoryUserRepository {
            index: 1,
            users: HashMap::default(),
        }
    }
}

impl InMemoryUserRepository {
    fn save(&mut self, user: User<Fresh>) -> Result<(), &'static str> {
        self.index += 1;
        let conserve_user = user.set_id(self.index);
        self.users.insert(self.index, conserve_user);
        Ok(())
    }
    fn get_idx(&self) -> u32 {
        self.index
    }
}

pub trait Persistence {}

struct Fresh;
struct Conserved;

impl Persistence for Fresh {}
impl Persistence for Conserved {}

pub struct User<P: Persistence> {
    id: Option<u32>,
    name: String,
    _state: PhantomData<P>,
}

impl User<Fresh> {
    fn new(name: String) -> Self {
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

#[cfg(test)]
mod tests {
    use super::InMemoryUserRepository;
    use super::User;

    #[test]
    fn can_add_user_to_repo() {
        let user = User::new("Marty".to_string());
        let mut repo = InMemoryUserRepository::default();

        assert_eq!(0, repo.users.len());
        assert_eq!(1, repo.get_idx());

        repo.save(user);
        assert_eq!(1, repo.users.len());
        assert_eq!(2, repo.get_idx());
    }
}
