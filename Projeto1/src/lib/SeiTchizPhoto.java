/**
 * Seguranca e Confiabilidade 2020/21
 * Trabalho 1
 * 
 * @author Catarina Lima 52787
 * @author Andre Silva 52809
 * @author Joao Oliveira 52839
 */

package lib;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class SeiTchizPhoto implements Serializable, Comparable<SeiTchizPhoto>{

	private static final long serialVersionUID = 1L;
	private String owner;
	private String id;
	private List<String> likes;
	private long creationDate;
	private byte[] hash;
	private String extension;

	public SeiTchizPhoto(byte[] image, String owner, String extension) throws IOException, NoSuchAlgorithmException {
		likes = new ArrayList<>();
		this.owner = owner;
		creationDate = new Date().getTime();
		this.id = owner + "_" + creationDate;
		this.extension = extension;

		MessageDigest md = MessageDigest.getInstance("SHA");
		this.hash = md.digest(image);

		//ClientPhotoFiles
		FileOutputStream fos = new FileOutputStream("ClientPhotoFiles/" + id + "."+ extension);
		fos.write(image);
		fos.close();
	}

	protected void like(String user) {

		if(!likes.contains(user))
			likes.add(user);
	}

	public byte[] getPhoto() throws IOException, NoSuchAlgorithmException {

		MessageDigest md = MessageDigest.getInstance("SHA");

		File photo = new File("ClientPhotoFiles/" + id + "."+ extension);

		byte[] photoFile;

		try {

			photoFile = Files.readAllBytes(photo.toPath());

		}catch (NoSuchFileException e) {
			return null;		
		}

		if(MessageDigest.isEqual(md.digest(photoFile), this.hash)) {
			return photoFile;
		}

		return null;

	}

	public String getOwner() {

		return owner;
	}

	public long getCreationDate() {

		return creationDate;
	}

	public String getId() {

		return id;
	}

	public int getLikes() {

		return likes.size();
	}

	public String getExtension() {

		return extension;
	}

	protected List<String> getLikedBy() {

		return likes;
	}

	@Override
	public int compareTo(SeiTchizPhoto o) {
		if(this.creationDate < o.creationDate)
			return -1;
		else if(this.creationDate > o.creationDate)
			return 1;

		return 0;
	}

}
