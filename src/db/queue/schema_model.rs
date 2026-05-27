#[derive(Clone, Copy)]
pub(in crate::db::queue) struct RequiredColumn {
    pub(in crate::db::queue) name: &'static str,
    pub(in crate::db::queue) data_type: &'static str,
    pub(in crate::db::queue) is_nullable: bool,
    pub(in crate::db::queue) collation_required: bool,
}

#[derive(Clone, Debug)]
pub(in crate::db::queue) struct ActualColumn {
    pub(in crate::db::queue) name: String,
    pub(in crate::db::queue) data_type: String,
    pub(in crate::db::queue) is_nullable: bool,
    pub(in crate::db::queue) collation: Option<String>,
}
