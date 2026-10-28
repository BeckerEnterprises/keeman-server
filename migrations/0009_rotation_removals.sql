-- The accounts an open rotation is to remove. While the rotation is open,
-- they write no batches (a member could otherwise keep the revision moving
-- and so block its own removal), open no rotation and append no roles
-- statement; the commit removes at most them. JSON list of user IDs.
ALTER TABLE rotations ADD COLUMN remove_user_ids TEXT NOT NULL DEFAULT '[]';
