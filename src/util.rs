pub struct RunOnDrop<T: FnOnce() -> RV, RV>(Option<T>);

impl<T: FnOnce() -> RV, RV> RunOnDrop<T, RV> {
    pub fn new(f: T) -> Self {
        Self(Some(f))
    }

    pub fn run(mut self) -> RV {
        (self.0.take().unwrap())()
    }
}

impl<T: FnOnce() -> RV, RV> std::ops::Drop for RunOnDrop<T, RV> {
    fn drop(&mut self) {
        if let Some(f) = self.0.take() {
            f();
        }
    }
}
