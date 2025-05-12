package rpv.utils;

import java.net.URL;

import javax.swing.ImageIcon;

public class RpvMedia
{
    public static ImageIcon getImageIcon(String name)
    {
        URL imageUrl = RpvMedia.class.getResource(String.format("/images/%s.png", name));
        return new ImageIcon(imageUrl);
    }
}
