/**
 * Seguranca e Confiabilidade 2020/21
 * Trabalho 1
 * 
 * @author Catarina Lima 52787
 * @author Andre Silva 52809
 * @author Joao Oliveira 52839
 */

package lib;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public class Client implements Serializable{

	private static final long serialVersionUID = 1L;
	private String username;

	private ArrayList<String> followers;
	private ArrayList<String> following;

	private ArrayList<SeiTchizPhoto> photos;

	private ArrayList<String> ownerGroups;
	private ArrayList<String> groups;

	public Client(String username) {
		
		this.username = username;
		followers = new ArrayList<>();
		following = new ArrayList<>();
		photos = new ArrayList<>();
		ownerGroups = new ArrayList<>();
		groups = new ArrayList<>();
	}

	public boolean newFollower(String userId) {

		if(followers.contains(userId))
			return false;

		return followers.add(userId);
	}	

	public boolean removeFollower(String userId) {

		return followers.remove(userId);
	}

	public boolean follow(String userId) {

		if(following.contains(userId))
			return false;

		return following.add(userId);
	}

	public boolean unfollow(String userId) {

		if(following.contains(userId)) {
			following.remove(userId);
			return true;
		}

		return false;
	}

	public List<String> listFollowers() {

		return followers;
	}

	public boolean addPhoto(SeiTchizPhoto photo) {

		return photos.add(photo);
	}

	public String getUsername() {

		return username;
	}

	public boolean addLikeToPhoto(String photoID, String likedByUser) {

		for(SeiTchizPhoto photo : photos) {
			if(photo.getId().equals(photoID)) {
				photo.like(likedByUser);
				return true;
			}
		}

		return false;
	}	


	public List<SeiTchizPhoto> getPhotos(){
		return photos;

	}

	public boolean isOwner (String idG) {
		return ownerGroups.contains(idG);
	}

	public void newGroupAsOwner(String id) {
		ownerGroups.add(id);	
	}

	public void newGroup(String id) {
		groups.add(id);
	}

	public void removeGroup(String id) {
		groups.remove(id);
	}

	public List<String> groupsIOwn() {
		return ownerGroups;
	}

	public List<String> groups() {
		return groups;
	}

	public List<String> getFollowingUsers() {
		return following;
	}

}
