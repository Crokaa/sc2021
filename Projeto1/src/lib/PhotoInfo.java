/**
 * Seguranca e Confiabilidade 2020/21
 * Trabalho 1
 * 
 * @author Catarina Lima 52787
 * @author Andre Silva 52809
 * @author Joao Oliveira 52839
 */

package lib;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.Serializable;

public class PhotoInfo implements Serializable{

	private static final long serialVersionUID = 1L;
	private int likes;
	private byte[] photo;
	private String id;
	private String owner;
	private String extension;

	public PhotoInfo(byte[] photo, int likes, String owner, String id, String extension) {

		this.likes = likes;
		this.photo = photo;
		this.id = id;
		this.owner = owner;
		this.extension = extension;
	}

	public int getLikes() {
		return likes;
	}

	public byte[] getPhoto() {
		return photo;
	}

	public String getId() {
		return id;
	}

	public String getOwner() {
		return owner;
	}

	public String getExtension() {
		return extension;
	}

	public void saveImageFileToDisk(String pathToSave) throws IOException {

		FileOutputStream fos = new FileOutputStream(pathToSave + id + "."+ extension);
		fos.write(photo);
		fos.close();
	}

}
