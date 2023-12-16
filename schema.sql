create table bundles(
	uuid text primary key
);

create table blobs(
	id integer primary key,

	bundle_uuid text, -- May be null if the blob has not been assigned to a bundle yet
	size integer not null,
	hash text not null,

	constraint UK__blobs__hash unique(hash),
	constraint FK__blobs__bundle_uuid foreign key(bundle_uuid) references bundles(uuid)
);


create table remote_files(
	id integer primary key,

	filepath blob not null,
	kind char not null, -- d: directory, f: regular file, l: symbolic link

	-- Only used if kind=f
	fsize integer,
	mtime integer,
	executable integer,

	-- Only used if kind=l
	link_target blob,

	constraint UK__remote_files_filepath unique(filepath)
);


create table remote_file_blobs(
	file_id integer not null,
	blob_id integer not null,

	constraint FK__remote_file_blobs__file_id foreign key(file_id) references remote_files(id) on delete cascade,
	constraint FK__remote_file_blobs__blob_id foreign key(blob_id) references blobs(id)
);
create index remote_file_blobs__blob_id on remote_file_blobs(blob_id);


create table local_files(
	id integer primary key,

	filepath blob not null,
	kind integer not null, -- d: directory, f: regular file, l: symbolic link

	-- Only used if kind=f
	size integer,
	mtime integer,
	ctime integer,
	inode integer,
	executable integer,

	-- Only used if kind=l
	link_target blob,

	-- Only used temporarily when updating the db from the filesystem
	still_exists integer not null default 1,

	constraint UK__local_files_filepath unique(filepath)
);


create table local_file_blobs(
	file_id integer not null,
	blob_id integer not null,

	constraint FK__local_file_blobs__file_id foreign key(file_id) references local_files(id) on delete cascade,
	constraint FK__local_file_blobs__blob_id foreign key(blob_id) references blobs(id)
);
create index local_file_blobs__blob_id on local_file_blobs(blob_id);
